#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "queue.h"
#include "unix-manager.h"

#define UNIX_PROTO_VERSION_LENGTH 200
#define UNIX_PROTO_VERSION_V1 "v1"
#define UNIX_PROTO_V1 1
#define CLIENT_BUFFER_SIZE 4096

// MSG_NOSIGNAL does not exists on OS X
#ifdef OS_DARWIN
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif
#endif

typedef struct Command
{
    char *name;
    int (*func)(cJSON *, cJSON *, void *);
    void *data;
    TAILQ_ENTRY(Command) next;
} command_t;

typedef struct UnixClient
{
    int fd;
    int version;
    char buf[CLIENT_BUFFER_SIZE];
    TAILQ_ENTRY(UnixClient) next;
} unix_client_t;

typedef struct UnixManager
{
    time_t start_timestamp;
    int socket;
    struct sockaddr_un client_addr;
    int select_max;

    TAILQ_HEAD(, Command) commands;
    TAILQ_HEAD(, UnixClient) clients;
} unix_manager_t;

static unix_manager_t unix_mgr;

static int unix_manager_new(unix_manager_t *this, const char *socket_file)
{
    this->start_timestamp = time(NULL);
    this->socket = -1;
    this->select_max = 0;

    TAILQ_INIT(&this->commands);
    TAILQ_INIT(&this->clients);

    unlink(socket_file);

    // set address
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_file, sizeof(addr.sun_path));
    addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    socklen_t len = (socklen_t)(strlen(addr.sun_path) + sizeof(addr.sun_family) + 1);

    // create socket
    this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->socket == -1)
    {
        log_error("unix socket: unable to create UNIX socket %s: %s", addr.sun_path, strerror(errno));
        return -1;
    }
    this->select_max = this->socket + 1;

    // set reuse option
    int on = 1;
    int ret = setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    if (ret != 0)
        log_warn("cannot set sockets options: %s.", strerror(errno));

    // bind socket
    ret = bind(this->socket, (struct sockaddr *)&addr, len);
    if (ret == -1)
    {
        log_error("unix socket: UNIX socket bind(%s) error: %s", socket_file, strerror(errno));
        return -1;
    }

    // listen
    if (listen(this->socket, 1) == -1)
    {
        log_error("command server: UNIX socket listen() error: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void unix_manager_set_max_fd(unix_manager_t *this)
{
    if (this == NULL)
    {
        log_warn("unix Manager is NULL, warn devel");
        return;
    }

    unix_client_t *item;
    this->select_max = this->socket + 1;
    TAILQ_FOREACH(item, &this->clients, next)
    {
        if (item->fd >= this->select_max)
        {
            this->select_max = item->fd + 1;
        }
    }
}

static unix_client_t *unix_client_new(void)
{
    unix_client_t *c = calloc(1, sizeof(unix_client_t));
    if (c == NULL)
    {
        log_error("can't allocate new client");
        return NULL;
    }
    return c;
}

static void unix_client_free(unix_client_t *c)
{
    if (c != NULL)
    {
        free(c);
    }
}

static void unix_client_delete(unix_manager_t *this, int fd)
{
    unix_client_t *item;
    int found = 0;

    TAILQ_FOREACH(item, &this->clients, next)
    {
        if (item->fd == fd)
        {
            found = 1;
            break;
        }
    }

    if (found == 0)
    {
        log_error("No fd found in client list");
        return;
    }

    TAILQ_REMOVE(&this->clients, item, next);

    close(item->fd);
    unix_manager_set_max_fd(this);
    unix_client_free(item);
}

static int unix_client_send(unix_client_t *client, cJSON *msg)
{
    bool ok = cJSON_PrintPreallocated(msg, client->buf, CLIENT_BUFFER_SIZE - 1, false);
    if (!ok)
    {
        log_warn("json dumps error");
        return -1;
    }
    size_t length = strlen(client->buf);
    if (length >= CLIENT_BUFFER_SIZE - 1)
    {
        log_warn("message is too large");
        return -1;
    }
    client->buf[length] = '\n';
    client->buf[length + 1] = '\0';

    if (send(client->fd, client->buf, length + 1, MSG_NOSIGNAL) == -1)
    {
        log_warn("send message error: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int unix_manager_accept(unix_manager_t *this)
{
    // accept client socket
    socklen_t len = sizeof(this->client_addr);
    int client_fd = accept(this->socket, (struct sockaddr *)&this->client_addr, &len);
    if (client_fd < 0)
    {
        log_error("unix socket: accept() error: %s", strerror(errno));
        return -1;
    }

    // read client version
    char buffer[UNIX_PROTO_VERSION_LENGTH + 1];
    buffer[sizeof(buffer) - 1] = 0;
    int ret = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (ret < 0)
    {
        log_error("command server: client doesn't send version");
        close(client_fd);
        return -1;
    }
    if (ret >= (int)(sizeof(buffer) - 1))
    {
        log_error("command server: client message is too long, disconnect it.");
        close(client_fd);
        return -1;
    }
    buffer[ret] = 0;

    // check request
    const char *error_pointer = NULL;
    cJSON *client_msg = cJSON_ParseWithOpts(buffer, &error_pointer, false);
    if (!client_msg)
    {
        log_error("invalid handshake message: %s", error_pointer);
        close(client_fd);
        return -1;
    }
    cJSON *version_obj = cJSON_GetObjectItemCaseSensitive(client_msg, "version");
    if (!cJSON_IsString(version_obj))
    {
        log_error("error: version is not a string");
        cJSON_Delete(client_msg);
        close(client_fd);
        return -1;
    }

    char *version = version_obj->valuestring;
    int client_version;
    if (strcmp(version, UNIX_PROTO_VERSION_V1) == 0)
    {
        client_version = UNIX_PROTO_V1;
    }
    else
    {
        log_error("error: invalid client version: %s", version);
        cJSON_Delete(client_msg);
        close(client_fd);
        return -1;
    }

    cJSON_Delete(client_msg);

    // send response
    cJSON *server_msg = cJSON_CreateObject();
    if (!server_msg)
    {
        log_error("create json object error");
        close(client_fd);
        return -1;
    }
    cJSON *status_obj = cJSON_CreateString("OK");
    if (!status_obj)
    {
        log_error("create json string error");
        cJSON_Delete(server_msg);
        close(client_fd);
        return -1;
    }
    cJSON_AddItemToObject(server_msg, "status", status_obj);

    unix_client_t *client = unix_client_new();
    if (client == NULL)
    {
        cJSON_Delete(server_msg);
        close(client_fd);
        return -1;
    }
    client->fd = client_fd;
    client->version = client_version;

    if (unix_client_send(client, server_msg) != 0)
    {
        log_error("unable to send command");
        cJSON_Delete(server_msg);
        unix_client_free(client);
        close(client_fd);
        return -1;
    }

    cJSON_Delete(server_msg);

    TAILQ_INSERT_TAIL(&this->clients, client, next);
    unix_manager_set_max_fd(this);
    return 0;
}

static int unix_command_execute(unix_manager_t *this, char *command, unix_client_t *client)
{
    cJSON *server_msg = cJSON_CreateObject();
    if (server_msg == NULL)
    {
        log_error("create json object error");
        return -1;
    }

    const char *error_pointer = NULL;
    cJSON *cmd_msg = cJSON_ParseWithOpts(command, &error_pointer, false);
    if (!cmd_msg)
    {
        log_error("invalid command: %s", error_pointer);
        goto error;
    }
    cJSON *cmd_obj = cJSON_GetObjectItemCaseSensitive(cmd_msg, "command");
    if (!cJSON_IsString(cmd_obj))
    {
        log_error("error: command is not a string");
        goto err_cmd;
    }
    char *cmd_name = cmd_obj->valuestring;

    int fret = -1;
    int found = 0;
    command_t *cmd;
    TAILQ_FOREACH(cmd, &this->commands, next)
    {
        if (!strcmp(cmd_name, cmd->name))
        {
            found = 1;
            fret = cmd->func(cmd_msg, server_msg, cmd->data);
            break;
        }
    }

    if (found == 0)
    {
        cJSON *msg_obj = cJSON_CreateString("unknown command");
        if (!msg_obj)
            goto err_cmd;

        cJSON_AddItemToObject(server_msg, "message", msg_obj);

        cJSON *status_obj = cJSON_CreateString("ERROR");
        if (!status_obj)
            goto err_cmd;

        cJSON_AddItemToObject(server_msg, "status", status_obj);
    }
    else if (fret != 0)
    {
        cJSON *msg_obj = cJSON_CreateString("ERROR");
        if (!msg_obj)
            goto err_cmd;

        cJSON_AddItemToObject(server_msg, "status", msg_obj);
    }
    else
    {
        cJSON *msg_obj = cJSON_CreateString("OK");
        if (!msg_obj)
            goto err_cmd;

        cJSON_AddItemToObject(server_msg, "status", msg_obj);
    }

    if (unix_client_send(client, server_msg) != 0)
        goto err_cmd;

    cJSON_Delete(cmd_msg);
    cJSON_Delete(server_msg);
    return 0;

err_cmd:
    cJSON_Delete(cmd_msg);
error:
    cJSON_Delete(server_msg);
    unix_client_delete(this, client->fd);
    return -1;
}

static void unix_client_recv(unix_manager_t *this, unix_client_t *client)
{
    char buffer[4096];
    int try = 0;
    int offset = 0;
    int cmd_over = 0;
    ssize_t ret;

    ret = recv(client->fd, buffer + offset, sizeof(buffer) - offset - 1, 0);
    do
    {
        if (ret <= 0)
        {
            if (ret == 0)
                log_debug("unix socket: lost connection with client");
            else
                log_error("unix socket: error on recv() from client: %s", strerror(errno));
            unix_client_delete(this, client->fd);
            return;
        }
        if (ret >= (int)(sizeof(buffer) - offset - 1))
        {
            log_error("Command server: client command is too long, disconnect it.");
            unix_client_delete(this, client->fd);
            return;
        }

        if (buffer[ret - 1] == '\n')
        {
            buffer[ret - 1] = 0;
            cmd_over = 1;
        }
        else
        {
            struct timeval tv;
            fd_set select_set;
            offset += ret;
            do
            {
                FD_ZERO(&select_set);
                FD_SET(client->fd, &select_set);
                tv.tv_sec = 0;
                tv.tv_usec = 500 * 1000;
                try++;
                ret = select(client->fd, &select_set, NULL, NULL, &tv);
                /* catch select() error */
                if (ret == -1)
                {
                    /* Signal was caught: just ignore it */
                    if (errno != EINTR)
                    {
                        log_info("Unix socket: lost connection with client");
                        unix_client_delete(this, client->fd);
                        return;
                    }
                }
            } while (ret == 0 && try < 3);

            if (ret > 0)
            {
                ret = recv(client->fd, buffer + offset, sizeof(buffer) - offset - 1, 0);
            }
        }
    } while (try < 3 && cmd_over == 0);

    if (try == 3 && cmd_over == 0)
    {
        log_info("Unix socket: incomplete client message, closing connection");
        unix_client_delete(this, client->fd);
        return;
    }

    unix_command_execute(this, buffer, client);
}

static int unix_manager_main(unix_manager_t *this)
{
    unix_client_t *uclient;
    unix_client_t *tclient;

    // Wait activity on the socket
    fd_set select_set;
    FD_ZERO(&select_set);
    FD_SET(this->socket, &select_set);
    TAILQ_FOREACH(uclient, &this->clients, next) { FD_SET(uclient->fd, &select_set); }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000;
    int ret = select(this->select_max, &select_set, NULL, NULL, &tv);
    if (ret == -1)
    {
        /* Signal was caught: just ignore it */
        if (errno == EINTR)
            return 0;

        log_error("command server: select() fatal error: %s", strerror(errno));
        return -1;
    }

    // timeout: continue
    if (ret == 0)
        return 0;

    TAILQ_FOREACH_SAFE(uclient, &this->clients, next, tclient)
    {
        if (FD_ISSET(uclient->fd, &select_set))
            unix_client_recv(this, uclient);
    }

    if (FD_ISSET(this->socket, &select_set))
        unix_manager_accept(this);

    return 0;
}

static void *unix_manager_run(void *arg)
{
    while (1)
    {
        int ret = unix_manager_main(&unix_mgr);
        if (ret != 0)
        {
            log_error("fatal error on unix socket");
            unix_client_t *item;
            unix_client_t *titem;
            TAILQ_FOREACH_SAFE(item, &(&unix_mgr)->clients, next, titem)
            {
                close(item->fd);
                free(item);
            }
            break;
        }
    }
}

int unix_manager_init(const char *socket_file)
{
    if (unix_manager_new(&unix_mgr, socket_file) != 0)
    {
        return -1;
    }
    return 0;
}

int unix_manager_register_command(const char *cmd_name, int (*func)(cJSON *, cJSON *, void *), void *data)
{
    if (func == NULL)
    {
        log_error("null command function");
        return -1;
    }

    if (cmd_name == NULL)
    {
        log_error("null command name");
        return -1;
    }

    command_t *lcmd = NULL;
    TAILQ_FOREACH(lcmd, &unix_mgr.commands, next)
    {
        if (!strcmp(cmd_name, lcmd->name))
        {
            log_error("command %s already registered", cmd_name);
            return -1;
        }
    }

    command_t *cmd = malloc(sizeof(command_t));
    if (cmd == NULL)
    {
        log_error("can't alloc command");
        return -1;
    }
    cmd->name = strdup(cmd_name);
    if (cmd->name == NULL)
    {
        log_error("can't alloc command name");
        free(cmd);
        return -1;
    }
    cmd->func = func;
    cmd->data = data;

    TAILQ_INSERT_TAIL(&unix_mgr.commands, cmd, next);
    return 0;
}

int unix_manager_thread_spawn()
{
    pthread_t thread_id;
    int ret = pthread_create(&thread_id, NULL, unix_manager_run, NULL);
    if (ret != 0)
    {
        log_error("failed to spawn Unix manager thread: %s", strerror(errno));
        return -1;
    }
    return 0;
}