/* ssh_client.c */

/*
 * Copyright 2003-2015 Aris Adamantiadis
 *
 * This file is part of the SSH Library
 *
 * You are free to copy this file, modify it in any way, consider it being public
 * domain. This does not apply to the rest of the library though, but it is
 * allowed to cut-and-paste working code from this file to any license of
 * program.
 * The goal is to show the API in action. It's not a reference on how terminal
 * clients must be made or how a client should react.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>
#include <sys/time.h>


#include <termios.h>

#include <unistd.h>

#include <pty.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>


#include "examples_common.h"
#define MAXCMD 10

static char *host;
static char *user;
static char *cmds[MAXCMD];
static struct termios terminal;

static char *pcap_file = NULL;

static char *proxycommand;

int authenticate_kbdint(ssh_session session, const char *password)
{
    int err;

    err = ssh_userauth_kbdint(session, NULL, NULL);
    while (err == SSH_AUTH_INFO) {
        const char *instruction;
        const char *name;
        char buffer[128];
        int i, n;

        name = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        n = ssh_userauth_kbdint_getnprompts(session);

        if (name && strlen(name) > 0) {
            printf("%s\n", name);
        }

        if (instruction && strlen(instruction) > 0) {
            printf("%s\n", instruction);
        }

        for (i = 0; i < n; i++) {
            const char *answer;
            const char *prompt;
            char echo;

            prompt = ssh_userauth_kbdint_getprompt(session, i, &echo);
            if (prompt == NULL) {
                break;
            }

            if (echo) {
                char *p;

                printf("%s", prompt);

                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    return SSH_AUTH_ERROR;
                }

                buffer[sizeof(buffer) - 1] = '\0';
                if ((p = strchr(buffer, '\n'))) {
                    *p = '\0';
                }

                if (ssh_userauth_kbdint_setanswer(session, i, buffer) < 0) {
                    return SSH_AUTH_ERROR;
                }

                memset(buffer, 0, strlen(buffer));
            } else {
                if (password && strstr(prompt, "Password:")) {
                    answer = password;
                } else {
                    buffer[0] = '\0';

                    if (ssh_getpass(prompt, buffer, sizeof(buffer), 0, 0) < 0) {
                        return SSH_AUTH_ERROR;
                    }
                    answer = buffer;
                }
                err = ssh_userauth_kbdint_setanswer(session, i, answer);
                memset(buffer, 0, sizeof(buffer));
                if (err < 0) {
                    return SSH_AUTH_ERROR;
                }
            }
        }
        err=ssh_userauth_kbdint(session,NULL,NULL);
    }

    return err;
}

static int auth_keyfile(ssh_session session, char* keyfile)
{
    ssh_key key = NULL;
    char pubkey[132] = {0}; // +".pub"
    int rc;

    snprintf(pubkey, sizeof(pubkey), "%s.pub", keyfile);

    rc = ssh_pki_import_pubkey_file( pubkey, &key);

    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;

    rc = ssh_userauth_try_publickey(session, NULL, key);

    ssh_key_free(key);

    if (rc!=SSH_AUTH_SUCCESS)
        return SSH_AUTH_DENIED;

    rc = ssh_pki_import_privkey_file(keyfile, NULL, NULL, NULL, &key);

    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;

    rc = ssh_userauth_publickey(session, NULL, key);

    ssh_key_free(key);

    return rc;
}


static void error(ssh_session session)
{
    fprintf(stderr,"Authentication failed: %s\n",ssh_get_error(session));
}

int authenticate_console(ssh_session session)
{
    int rc;
    int method;
    char password[128] = {0};
    char *banner;

    // Try to authenticate
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_AUTH_ERROR) {
        error(session);
        return rc;
    }

    method = ssh_userauth_list(session, NULL);
    while (rc != SSH_AUTH_SUCCESS) {
        if (method & SSH_AUTH_METHOD_GSSAPI_MIC){
            rc = ssh_userauth_gssapi(session);
            if(rc == SSH_AUTH_ERROR) {
                error(session);
                return rc;
            } else if (rc == SSH_AUTH_SUCCESS) {
                break;
            }
        }
        // Try to authenticate with public key first
        if (method & SSH_AUTH_METHOD_PUBLICKEY) {
            rc = ssh_userauth_publickey_auto(session, NULL, NULL);
            if (rc == SSH_AUTH_ERROR) {
                error(session);
                return rc;
            } else if (rc == SSH_AUTH_SUCCESS) {
                break;
            }
        }
        {
            char buffer[128] = {0};
            char *p = NULL;

            printf("Automatic pubkey failed. "
                   "Do you want to try a specific key? (y/n)\n");
            if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                break;
            }
            if ((buffer[0]=='Y') || (buffer[0]=='y')) {
                printf("private key filename: ");

                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    return SSH_AUTH_ERROR;
                }

                buffer[sizeof(buffer) - 1] = '\0';
                if ((p = strchr(buffer, '\n'))) {
                    *p = '\0';
                }

                rc = auth_keyfile(session, buffer);

                if(rc == SSH_AUTH_SUCCESS) {
                    break;
                }
                fprintf(stderr, "failed with key\n");
            }
        }

        // Try to authenticate with keyboard interactive";
        if (method & SSH_AUTH_METHOD_INTERACTIVE) {
            rc = authenticate_kbdint(session, NULL);
            if (rc == SSH_AUTH_ERROR) {
                error(session);
                return rc;
            } else if (rc == SSH_AUTH_SUCCESS) {
                break;
            }
        }

        if (ssh_getpass("Password: ", password, sizeof(password), 0, 0) < 0) {
            return SSH_AUTH_ERROR;
        }

        // Try to authenticate with password
        if (method & SSH_AUTH_METHOD_PASSWORD) {
            rc = ssh_userauth_password(session, NULL, password);
            if (rc == SSH_AUTH_ERROR) {
                error(session);
                return rc;
            } else if (rc == SSH_AUTH_SUCCESS) {
                break;
            }
        }
        memset(password, 0, sizeof(password));
    }

    banner = ssh_get_issue_banner(session);
    if (banner) {
        printf("%s\n",banner);
        ssh_string_free_char(banner);
    }

    return rc;
}

int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    char buf[10];
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    state = ssh_session_is_known_server(session);

    switch(state) {
        case SSH_KNOWN_HOSTS_CHANGED:
            fprintf(stderr,"Host key for server changed : server's one is now :\n");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
            ssh_clean_pubkey_hash(&hash);
            fprintf(stderr,"For security reason, connection will be stopped\n");
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
            fprintf(stderr,"An attacker might change the default server key to confuse your client"
                           "into thinking the key does not exist\n"
                           "We advise you to rerun the client with -d or -r for more safety.\n");
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
            fprintf(stderr,"the file will be automatically created.\n");
            /* fallback to SSH_SERVER_NOT_KNOWN behavior */
            break;
        case SSH_SERVER_NOT_KNOWN:
            fprintf(stderr,
                    "The server is unknown. Do you trust the host key (yes/no)?\n");
            ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);

            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                ssh_clean_pubkey_hash(&hash);
                return -1;
            }
            if(strncasecmp(buf,"yes",3)!=0){
                ssh_clean_pubkey_hash(&hash);
                return -1;
            }
            fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
                ssh_clean_pubkey_hash(&hash);
                return -1;
            }
            if(strncasecmp(buf,"yes",3)==0){
                rc = ssh_session_update_known_hosts(session);
                if (rc != SSH_OK) {
                    ssh_clean_pubkey_hash(&hash);
                    fprintf(stderr, "error %s\n", strerror(errno));
                    return -1;
                }
            }

            break;
        case SSH_KNOWN_HOSTS_ERROR:
            ssh_clean_pubkey_hash(&hash);
            fprintf(stderr,"%s",ssh_get_error(session));
            return -1;
        case SSH_KNOWN_HOSTS_OK:
            break; /* ok */
    }

    ssh_clean_pubkey_hash(&hash);

    return 0;
}

static int auth_callback(const char *prompt,
                         char *buf,
                         size_t len,
                         int echo,
                         int verify,
                         void *userdata)
{
    (void) verify;
    (void) userdata;

    return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb = {
        .auth_function = auth_callback,
        .userdata = NULL,
};

static void add_cmd(char *cmd)
{
    int n;

    for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

    if (n == MAXCMD) {
        return;
    }

    cmds[n] = strdup(cmd);
}

static void usage(void)
{
    fprintf(stderr,
            "Usage : ssh [options] [login@]hostname\n"
            "sample client - libssh-%s\n"
            "Options :\n"
            "  -l user : log in as user\n"
            "  -p port : connect to port\n"
            "  -d : use DSS to verify host public key\n"
            "  -r : use RSA to verify host public key\n"
            #ifdef WITH_PCAP
            "  -P file : create a pcap debugging file\n"
            #endif
            #ifndef _WIN32
            "  -T proxycommand : command to execute as a socket proxy\n"
            #endif
            "\n",
            ssh_version(0));

    exit(0);
}

static int opts(int argc, char **argv)
{
    int i;

    while((i = getopt(argc,argv,"T:P:")) != -1) {
        switch(i){
            case 'P':
                pcap_file = optarg;
                break;
#ifndef _WIN32
            case 'T':
                proxycommand = optarg;
                break;
#endif
            default:
                fprintf(stderr, "Unknown option %c\n", optopt);
                usage();
        }
    }
    if (optind < argc) {
        host = argv[optind++];
    }

    while(optind < argc) {
        add_cmd(argv[optind++]);
    }

    if (host == NULL) {
        usage();
    }

    return 0;
}

static void do_cleanup(int i)
{
    /* unused variable */
    (void) i;

    tcsetattr(0, TCSANOW, &terminal);
}

static void do_exit(int i)
{
    /* unused variable */
    (void) i;

    do_cleanup(0);
    exit(0);
}

static ssh_channel chan;
static int signal_delayed = 0;

static void sigwindowchanged(int i)
{
    (void) i;
    signal_delayed = 1;
}

static void setsignal(void)
{
    signal(SIGWINCH, sigwindowchanged);
    signal_delayed = 0;
}

static void sizechanged(void)
{
    struct winsize win = {
            .ws_row = 0,
    };

    ioctl(1, TIOCGWINSZ, &win);
    ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
    setsignal();
}

static void select_loop(ssh_session session,ssh_channel channel)
{
    ssh_connector connector_in, connector_out, connector_err;
    int rc;

    ssh_event event = ssh_event_new();

    /* stdin */
    connector_in = ssh_connector_new(session);
    ssh_connector_set_out_channel(connector_in, channel, SSH_CONNECTOR_STDOUT);
    ssh_connector_set_in_fd(connector_in, 0);
    ssh_event_add_connector(event, connector_in);

    /* stdout */
    connector_out = ssh_connector_new(session);
    ssh_connector_set_out_fd(connector_out, 1);
    ssh_connector_set_in_channel(connector_out, channel, SSH_CONNECTOR_STDOUT);
    ssh_event_add_connector(event, connector_out);

    /* stderr */
    connector_err = ssh_connector_new(session);
    ssh_connector_set_out_fd(connector_err, 2);
    ssh_connector_set_in_channel(connector_err, channel, SSH_CONNECTOR_STDERR);
    ssh_event_add_connector(event, connector_err);

    while (ssh_channel_is_open(channel)) {
        if (signal_delayed) {
            sizechanged();
        }
        rc = ssh_event_dopoll(event, 60000);
        if (rc == SSH_ERROR) {
            fprintf(stderr, "Error in ssh_event_dopoll()\n");
            break;
        }
    }
    ssh_event_remove_connector(event, connector_in);
    ssh_event_remove_connector(event, connector_out);
    ssh_event_remove_connector(event, connector_err);

    ssh_connector_free(connector_in);
    ssh_connector_free(connector_out);
    ssh_connector_free(connector_err);

    ssh_event_free(event);
}

static void shell(ssh_session session)
{
    ssh_channel channel;
    struct termios terminal_local;
    int interactive=isatty(0);

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return;
    }

    if (interactive) {
        tcgetattr(0, &terminal_local);
        memcpy(&terminal, &terminal_local, sizeof(struct termios));
    }

    if (ssh_channel_open_session(channel)) {
        printf("Error opening channel : %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }
    chan = channel;
    if (interactive) {
        ssh_channel_request_pty(channel);
        sizechanged();
    }

    if (ssh_channel_request_shell(channel)) {
        printf("Requesting shell : %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    if (interactive) {
        cfmakeraw(&terminal_local);
        tcsetattr(0, TCSANOW, &terminal_local);
        setsignal();
    }
    signal(SIGTERM, do_cleanup);
    select_loop(session, channel);
    if (interactive) {
        do_cleanup(0);
    }
    ssh_channel_free(channel);
}

static void batch_shell(ssh_session session)
{
    ssh_channel channel;
    char buffer[1024];
    size_t i;
    int s = 0;

    for (i = 0; i < MAXCMD && cmds[i]; ++i) {
        s += snprintf(buffer + s, sizeof(buffer) - s, "%s ", cmds[i]);
        free(cmds[i]);
        cmds[i] = NULL;
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return;
    }

    ssh_channel_open_session(channel);
    if (ssh_channel_request_exec(channel, buffer)) {
        printf("Error executing '%s' : %s\n", buffer, ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }
    select_loop(session, channel);
    ssh_channel_free(channel);
}

static int client(ssh_session session)
{
    int auth = 0;
    char *banner;
    int state;

    if (user) {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
            return -1;
        }
    }
    if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0) {
        return -1;
    }
    if (proxycommand != NULL) {
        if (ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand)) {
            return -1;
        }
    }
    ssh_options_parse_config(session, NULL);

    if (ssh_connect(session)) {
        fprintf(stderr, "Connection failed : %s\n", ssh_get_error(session));
        return -1;
    }

    state = verify_knownhost(session);
    if (state != 0) {
        return -1;
    }

    ssh_userauth_none(session, NULL);
    banner = ssh_get_issue_banner(session);
    if (banner) {
        printf("%s\n", banner);
        free(banner);
    }
    auth = authenticate_console(session);
    if (auth != SSH_AUTH_SUCCESS) {
        return -1;
    }
    if (cmds[0] == NULL) {
        shell(session);
    } else {
        batch_shell(session);
    }

    return 0;
}

static ssh_pcap_file pcap;
static void set_pcap(ssh_session session)
{
    if (pcap_file == NULL) {
        return;
    }

    pcap = ssh_pcap_file_new();
    if (pcap == NULL) {
        return;
    }

    if (ssh_pcap_file_open(pcap, pcap_file) == SSH_ERROR) {
        printf("Error opening pcap file\n");
        ssh_pcap_file_free(pcap);
        pcap = NULL;
        return;
    }
    ssh_set_pcap_file(session, pcap);
}

static void cleanup_pcap(void)
{
    if (pcap != NULL) {
        ssh_pcap_file_free(pcap);
    }
    pcap = NULL;
}

int main(int argc, char **argv)
{
    ssh_session session;

    session = ssh_new();

    ssh_callbacks_init(&cb);
    ssh_set_callbacks(session,&cb);

    if (ssh_options_getopt(session, &argc, argv)) {
        fprintf(stderr,
                "Error parsing command line: %s\n",
                ssh_get_error(session));
        usage();
    }
    opts(argc, argv);
    signal(SIGTERM, do_exit);

    set_pcap(session);
    client(session);

    ssh_disconnect(session);
    ssh_free(session);
    cleanup_pcap();

    ssh_finalize();

    return 0;
}
