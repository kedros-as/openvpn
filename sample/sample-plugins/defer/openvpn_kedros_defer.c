/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "openvpn-plugin.h"

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;

/*
 * Constants indicating minimum API and struct versions by the functions
 * in this plugin.  Consult openvpn-plugin.h, look for:
 * OPENVPN_PLUGIN_VERSION and OPENVPN_PLUGINv3_STRUCTVER
 *
 * Strictly speaking, this sample code only requires plugin_log, a feature
 * of structver version 1.  However, '1' lines up with ancient versions
 * of openvpn that are past end-of-support.  As such, we are requiring
 * structver '5' here to indicate a desire for modern openvpn, rather
 * than a need for any particular feature found in structver beyond '1'.
 */
#define OPENVPN_PLUGIN_VERSION_MIN 3
#define OPENVPN_PLUGIN_STRUCTVER_MIN 5

/*
 * Our context, where we keep our state.
 * In reality configuration only.
 */

struct plugin_context {
    char *script_userpass_path;
    char *script_learnaddress_path;
};

/* module name for plugin_log() */
static char *MODULE = "openvpn_kedros_defer";

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

/* Require a minimum OpenVPN Plugin API */
OPENVPN_EXPORT int
openvpn_plugin_min_version_required_v1()
{
    return OPENVPN_PLUGIN_VERSION_MIN;
}

/* use v3 functions so we can use openvpn's logging and base64 etc. */
OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct plugin_context *context;

    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;

    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_open_v3");

    /*
     * Allocate our context
     */
    context = (struct plugin_context *) calloc(1, sizeof(struct plugin_context));
    if (!context)
    {
        goto error;
    }
    if (args->argv[1] && args->argv[2]) {
        context->script_userpass_path = strdup(args->argv[1]);
        if (context->script_userpass_path == NULL)
            goto error;
        context->script_learnaddress_path = strdup(args->argv[2]);
        if (context->script_learnaddress_path == NULL)
            goto error;
    } else {
        plugin_log(PLOG_NOTE, MODULE, "2 arguments required - path to userpass executable and path to learn-address executable.");
        goto error;
    }

    /*
     * Which callbacks to intercept.
     */
    ret->type_mask =
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        |OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_LEARN_ADDRESS);

    ret->handle = (openvpn_plugin_handle_t *) context;
    plugin_log(PLOG_NOTE, MODULE, "initialization succeeded");
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

error:
    if (context->script_userpass_path)
        free(context->script_userpass_path);
    if (context->script_learnaddress_path)
        free(context->script_learnaddress_path);
    if (context)
        free(context);
    plugin_log(PLOG_NOTE, MODULE, "initialization failed");
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

static int
deferred_handler(const char *script, int mode, struct plugin_context *context,
                      const char *argv[], const char *envp[])
{
    const char *auth_control_file = get_env("auth_control_file", envp);

    if (mode == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && !auth_control_file)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* we do not want to complicate our lives with having to wait()
     * for child processes (so they are not zombiefied) *and* we MUST NOT
     * fiddle with signal handlers (= shared with openvpn main), so
     * we use double-fork() trick.
     */

    /* fork, sleep, succeed (no "real" auth done = always succeed) */
    pid_t p1 = fork();
    if (p1 < 0)                 /* Fork failed */
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (p1 > 0)                 /* parent process */
    {
        waitpid(p1, NULL, 0);
        if (mode == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
            return OPENVPN_PLUGIN_FUNC_DEFERRED;
        else
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }

    /* first gen child process, fork() again and exit() right away */
    pid_t p2 = fork();
    if (p2 < 0)
    {
        plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: fork(2) failed");
        exit(1);
    }

    if (p2 != 0)                            /* new parent: exit right away */
    {
        exit(0);
    }

    /* (grand-)child process
     *  - never call "return" now (would mess up openvpn)
     *  - return status is communicated by file
     *  - then exit()
     */

    /* do mighty complicated work that will really take time here... */
    plugin_log(PLOG_NOTE, MODULE, "in async/deferred handler, execve %s", script);
    execve(script, (char *const*)argv, (char *const*)envp);
    /*
     * Since we exec'ed we should never get here.  But just in case, exit hard.
     */
    plugin_log(PLOG_ERR|PLOG_ERRNO, MODULE, "BACKGROUND: execve(2) failed");
    exit(127);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int v3structver,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
    if (v3structver < OPENVPN_PLUGIN_STRUCTVER_MIN)
    {
        fprintf(stderr, "%s: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    const char **argv = args->argv;
    const char **envp = args->envp;
    struct plugin_context *context = (struct plugin_context *) args->handle;
    switch (args->type)
    {
        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            return deferred_handler(context->script_userpass_path, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, context, argv, envp);

        case OPENVPN_PLUGIN_LEARN_ADDRESS:
            return deferred_handler(context->script_learnaddress_path, OPENVPN_PLUGIN_LEARN_ADDRESS, context, argv, envp);

        default:
            plugin_log(PLOG_NOTE, MODULE, "OPENVPN_PLUGIN_?");
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    plugin_log(PLOG_NOTE, MODULE, "FUNC: openvpn_plugin_close_v1");
    
    free(context->script_userpass_path);
    free(context->script_learnaddress_path);
    free(context);
}
