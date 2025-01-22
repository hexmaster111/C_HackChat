#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define JSON_IMPL
#include "json.h"

#define PORT (8082)

#define HTTP_200_OK "HTTP/1.1 200 OK\r\n"
#define HTTP_404_ERR "HTTP/1.1 404 PAGE NOT FOUND\r\n"
#define CONTENT_TEXT_HTML "Content-Type: text/html\r\n"
#define CONTENT_TEXT_JSON "Content-Type: application/json\r\n"

#define SLICE_FMT "%.*s"
#define SLICE_PNT(SLICE) SLICE.buf ? SLICE.len : (int)sizeof("(null)"), SLICE.buf ? SLICE.buf : "(null)"
typedef struct Slice
{
    char *buf;
    int len;
} Slice;
typedef struct SlicePair
{
    Slice name, value;
} SlicePair;
#define SLICE(CLIT) \
    (Slice) { .buf = CLIT, .len = (sizeof(CLIT) / sizeof(CLIT[0])) - 1 }

// non-zero to be not match  ... tbh idk how memcmps output works, also we just match the parts
// of the shortest string, from the from
int slice_cmp(Slice a, Slice b)
{
    if (a.len != b.len)
        return 1;

    return memcmp(a.buf, b.buf, a.len);
}

int WriteBuffer(int fd, char *buffer, int bufferlen);

char *HttpUrlStringSearch(char *buf, int *out_methodlen)
{
    // we read upto the first space
    char *ret = buf;

    for (*out_methodlen = 0;
         buf[*out_methodlen] &&
         buf[*out_methodlen] != ' ' &&
         buf[*out_methodlen] != '=' /* url value seprator */ &&
         buf[*out_methodlen] != '&' /* param seprator */ &&
         buf[*out_methodlen] != '?' /* url param sepprator */;
         *out_methodlen += 1)
        ;

    return ret;
}

#define HTML_HEADER HTTP_200_OK CONTENT_TEXT_HTML "\r\n"
const int html_header_len = sizeof(HTML_HEADER) / sizeof(HTML_HEADER[0]);

int AppendHTMLHeaderAndWriteBuffer(int fd, char *buffer, int bufferlen)
{

    char *m = calloc(bufferlen + html_header_len, sizeof(char));

    if (!m)
        return -1;

    memcpy(m, HTML_HEADER, html_header_len);
    memcpy(m + html_header_len, buffer, bufferlen);

    int r = WriteBuffer(fd, m, bufferlen + html_header_len);

    free(m);

    return r;
}

// 0 ok, 0>ret bad
int WriteBuffer(int fd, char *buffer, int bufferlen)
{
    printf("responding to %d\n", fd);
    int out = 0;
    do
    {
        int o = write(fd, buffer, bufferlen - out);
        if (0 > o)
        {
            perror("WriteBuffer");
            return o;
        }
        out += o;
    } while (bufferlen > out);
    return 0;
}

int Write404(int fd)
{
#define error_404_html                   \
    HTTP_404_ERR CONTENT_TEXT_HTML       \
        "\r\n<!DOCTYPE html>\r\n"        \
        "<html>\r\n"                     \
        "<head></head>\r\n"              \
        "<body>\r\n"                     \
        "That Page dose not exist!!\r\n" \
        "</body>\r\n"                    \
        "</html>\r\n\r\n"

    return WriteBuffer(fd, error_404_html, sizeof(error_404_html) / sizeof(error_404_html[0]));
#undef error_404_html
}

int WriteHelloWorldHtml(int fd)
{
#define hello_world_html          \
    HTTP_200_OK CONTENT_TEXT_HTML \
        "\r\n<!DOCTYPE html>\r\n" \
        "<html>\r\n"              \
        "<head></head>\r\n"       \
        "<body>\r\n"              \
        "something else!\r\n"     \
        "</body>\r\n"             \
        "</html>\r\n\r\n"

    return WriteBuffer(fd, hello_world_html, sizeof(hello_world_html) / sizeof(hello_world_html[0]));
#undef hello_world_html
}

#include <fcntl.h>
#include <sys/stat.h>
typedef struct file_memmap
{
    int len, fd;
    char *map;
} file_memmap;
void CloseFileMemMap(file_memmap *fc)
{
    munmap(fc, fc->len);
    close(fc->fd);

    fc->map = NULL;
    fc->len = 0;
    fc->fd = 0;
}

// -1 on error 0 on ok
int OpenFileMemMap(file_memmap *fc, const char *fpath)
{
    int fd = open(fpath, O_RDONLY);

    if (fd == -1)
    {
        perror("open");
        return -1;
    }

    struct stat sb;

    if (fstat(fd, &sb) == -1)
    {
        perror("fstat");
        return -1;
    }

    void *map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (map == MAP_FAILED)
    {
        close(fd);
        return -1;
    }

    fc->map = (char *)map;
    fc->len = sb.st_size;
    fc->fd = fd;

    return 0;
}

int WriteFileDirectly(int fd, const char *fpath)
{
    file_memmap f;
    if (0 > OpenFileMemMap(&f, fpath))
    {
        perror("mmap");
        return -1;
    }
    int ret = AppendHTMLHeaderAndWriteBuffer(fd, f.map, f.len);
    CloseFileMemMap(&f);
    return ret;
}

#define MAX_MESSAGE_LEN (255)
#define MAX_NAME_LEN (25)
#define MAX_IP_LEN (16) // 192.168.100.200
#define MAX_SERVER_MESSAGES 500000

typedef struct Chat
{
    char
        message[MAX_MESSAGE_LEN],
        from_name[MAX_NAME_LEN],
        from_ip[MAX_IP_LEN];
} Chat;

Chat g_messages[MAX_SERVER_MESSAGES];
int g_next_chat = 0;

void InitMessages()
{
    g_next_chat = 0;
    memset(g_messages, 0, sizeof(g_messages));
}

int HackChat_PostMessage(int fd, struct sockaddr_in addr, Slice body)
{
    char *ptr;
    int len = 0;

    ParseJson(body.buf, body.len, "from", &ptr, &len);
    if (ptr)
        memcpy(g_messages[g_next_chat].from_name, ptr, len > MAX_NAME_LEN ? MAX_NAME_LEN : len);

    ParseJson(body.buf, body.len, "message", &ptr, &len);
    if (ptr)
        memcpy(g_messages[g_next_chat].message, ptr, len > MAX_MESSAGE_LEN ? MAX_MESSAGE_LEN : len);

    char *n = inet_ntoa(addr.sin_addr);
    len = strlen(n);

    memcpy(g_messages[g_next_chat].from_ip, n, len > MAX_IP_LEN ? MAX_IP_LEN : len);

    g_next_chat += 1;

#define ok_message HTTP_200_OK "\r\n"
    return WriteBuffer(fd, ok_message, sizeof(ok_message) / sizeof(ok_message[0]));
#undef ok_message
}

// #define resp HTTP_200_OK CONTENT_TEXT_JSON "\r\n[{\"fromid\":\"SomeHashOfTheSendersIp\", \"fromname\":\"the sender\",\"message\":\"The message that was sent\"}]"
// return WriteBuffer(fd, resp, sizeof(resp) / sizeof(resp[0]) - 1);
// #undef resp

/* writes our g_messages in memory down the wire */
int HackChat_WriteMessages(int fd)
{
    int size = 1024;
    char *buffer = calloc(1, size);
    if (!buffer)
    {
        puts("OUT OF MEMORY");
        return -1;
    }

    int i = 0;

#define resp_header HTTP_200_OK CONTENT_TEXT_JSON "\r\n"

#define jobject_array_start "["
#define jobject_array_end "]"

#define object_start "{"
#define object_end "}"

#define fromfieldname "\"fromname\":\""
#define fromidfieldname "\"fromid\":\""
#define messagefieldname "\"message\":\""

#define endfromfield "\","
#define endidfield "\","
#define endmessagefield "\"}"

#define array_another ","

    memcpy(buffer, resp_header, sizeof(resp_header) - 1);
    i += sizeof(resp_header) - 1;

    // [
    memcpy(buffer + i, jobject_array_start, sizeof(jobject_array_start) - 1);
    i += sizeof(jobject_array_start) - 1;

    for (int m = 0; m < g_next_chat; m++)
    {

        // re alloc
        if ((i + MAX_IP_LEN + MAX_MESSAGE_LEN + MAX_NAME_LEN) > size)
        {
            puts("realloc");

            size *= 2;
            buffer = realloc(buffer, size);

            if (!buffer)
            {
                puts("OUT OF MEMORY");
                return -1;
            }
        }

        Chat *c = &g_messages[m];

        int msglen = strlen(c->message);
        int iplen = strlen(c->from_ip);
        int fromlen = strlen(c->from_name);

        // [{
        memcpy(buffer + i, object_start, sizeof(object_start) - 1);
        i += sizeof(object_start) - 1;

        // [{ "fromname":"
        memcpy(buffer + i, fromfieldname, sizeof(fromfieldname) - 1);
        i += sizeof(fromfieldname) - 1;

        // [{ "fromname":"whatever goes in this field
        memcpy(buffer + i, c->from_name, fromlen);
        i += fromlen;

        // [{ "fromname":"whatever goes in this field",
        memcpy(buffer + i, endfromfield, sizeof(endfromfield) - 1);
        i += sizeof(endfromfield) - 1;

        // [{ "fromname":"whatever goes in this field","fromid":"
        memcpy(buffer + i, fromidfieldname, sizeof(fromidfieldname) - 1);
        i += sizeof(fromidfieldname) - 1;

        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123
        memcpy(buffer + i, c->from_ip, iplen);
        i += iplen;

        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123",
        memcpy(buffer + i, endidfield, sizeof(endidfield) - 1);
        i += sizeof(endidfield) - 1;

        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123","message":"
        memcpy(buffer + i, messagefieldname, sizeof(messagefieldname) - 1);
        i += sizeof(messagefieldname) - 1;

        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123","message":"The Message
        memcpy(buffer + i, c->message, msglen);
        i += msglen;

        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123","message":"The Message" }
        memcpy(buffer + i, endmessagefield, sizeof(endmessagefield) - 1);
        i += sizeof(endmessagefield) - 1;


        // [{ "fromname":"whatever goes in this field","fromid":"192.168.0.123","message":"The Message" }, 
        if (m < g_next_chat - 1)
        {
            /* this is NOT the last one */
            memcpy(buffer + i, array_another, sizeof(array_another) - 1);
            i += sizeof(array_another) - 1;
        }
    }

    memcpy(buffer + i, jobject_array_end, sizeof(jobject_array_end) - 1);
    i += sizeof(jobject_array_end) - 1;

    int rvalue = WriteBuffer(fd, buffer, i);

    free(buffer);
    return rvalue;

#undef resp_header
}

/* all strings in here are owned by the calling function, and must be coppied out */
void Route(
    int fd,
    Slice request,
    Slice method,
    Slice route,
    Slice body,
    int url_argc,
    SlicePair url_args[url_argc],
    struct sockaddr_in caddr)
{

    printf("Route " SLICE_FMT "\n", SLICE_PNT(route));
    printf("Method " SLICE_FMT "\n", SLICE_PNT(method));
    printf("Body " SLICE_FMT "\n", SLICE_PNT(body));
    // printf(SLICE_FMT "\n", SLICE_PNT(request));

    if (slice_cmp(SLICE("POST"), method) == 0 && slice_cmp(SLICE("/"), route) == 0)
    {
        HackChat_PostMessage(fd, caddr, body);
    }
    else if (slice_cmp(SLICE("GET"), method) == 0 && slice_cmp(SLICE("/messages"), route) == 0)
    {
        HackChat_WriteMessages(fd);
    }
    else if (slice_cmp(SLICE("GET"), method) == 0 && slice_cmp(SLICE("/"), route) == 0)
    {
        WriteFileDirectly(fd, "index.html");
    }
    else
    {
        Write404(fd);
    }

    close(fd);
}
/*
    returns NULL or body
*/
char *HttpGetBody(char *buf, int buflen, int *out_len)
{
    int bsi = 0;
    for (; bsi < buflen; bsi++)
    {
        if (buflen > bsi + 4 &&
            buf[bsi] == '\r' &&
            buf[bsi + 1] == '\n' &&
            buf[bsi + 2] == '\r' &&
            buf[bsi + 3] == '\n')
        {
            bsi += 4;
            goto found_body;
        }
    }

    *out_len = 0;
    return NULL;

found_body:
    *out_len = 0;
    char *bodystart = buf + bsi;
    *out_len = strlen(bodystart);
    return bodystart;
}

/* returns number of args found in buffer and saved to dst
    or -1 on error
*/
int HttpUrlGetArgs(char *buffer, int buflen, SlicePair *dst, int dstlen)
{
    // with args
    // "?something=yes HTTP/1.1"
    // without args
    // " HTTP/1.1"

    int nowlen, dstidx = 0;
    char *now = buffer;
    int kv = 0; /* toggles between 0 and 1 when we are reading keys and values */

    do
    {
        now = HttpUrlStringSearch(now, &nowlen);

        if (*now == ' ')
        {
            /* end of args */
            break;
        }
        else if (*now == '?' || *now == '&')
        {
            now += 1; // skip arg sepprator
        }
        else
        {
            if (kv == 0)
            {
                /* this is a key */
                int namelen;
                char *namestart = HttpUrlStringSearch(now, &namelen);
                dst[dstidx].name = (Slice){.buf = namestart, .len = namelen};
                kv = 1;
                now += namelen + 1; /* + 1 to skip the '='*/
            }
            else if (kv == 1)
            {
                /* this is a value */
                int vallen;
                char *valstart = HttpUrlStringSearch(now, &vallen);
                dst[dstidx].value = (Slice){.buf = valstart, .len = vallen};
                kv = 0;
                now += vallen;
                dstidx += 1; /* we got a kv, time to read another! */

                if (dstidx > dstlen)
                {
                    puts("Client sent more then dstlen args!");
                    return -1;
                }
            }
        }
    } while (*now != ' ');

    // puts(buffer);
    return dstidx;
}

void handle_request(int fd, struct sockaddr_in caddr)
{
    char buffer[1024] = {0};
    SlicePair args[128] = {0};

    // i think the first word is always the method, and then the route upto the next space?
    int r = read(fd, buffer, sizeof(buffer)-1);
    if (0 > r)
    {
        perror("read");
        exit(EXIT_FAILURE);
    }

    buffer[r] = '\0';

    // puts(buffer);

    int methodlen;
    int routelen;

    /* thease pointers are slices of buff, and there ends are set by methodlen and route len */
    char *method = HttpUrlStringSearch(buffer, &methodlen);
    char *route = HttpUrlStringSearch(buffer + methodlen + 1, &routelen);
    int used = methodlen + 1 + routelen;

    int argc = HttpUrlGetArgs(buffer + used, r - used, args, sizeof(args) / sizeof(args[0]));

    int bodylen;
    char *body = HttpGetBody(buffer, r, &bodylen);

    if (0 > argc)
    {
        close(fd);
        return;
    }

    if (!method || !route)
    {
        close(fd);
        return;
    }

    Route(fd,
          (Slice){.buf = buffer, .len = sizeof(buffer)},
          (Slice){.buf = method, .len = methodlen},
          (Slice){.buf = route, .len = routelen},
          (Slice){.buf = body, .len = bodylen},
          argc, args, caddr);
}

int main(int argc, char *argv[])
{
    InitMessages();
    int sfd, cfd;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in saddr, caddr;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > sfd)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (0 > setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

// Idk why intellasence cant find this... i can ctrl click it and it finds it...
// but it can find the other SO_
#ifndef SO_REUSEPORT
#define SO_REUSEPORT (15)
#endif

    if (0 > setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(PORT);

    if (0 > bind(sfd, (struct sockaddr *)&saddr, addr_len))
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (0 > listen(sfd, 1))
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        cfd = accept(sfd, (struct sockaddr *)&caddr, &addr_len);
        if (0 > cfd)
        {
            perror("accept");
            continue;
        }

        // puts(inet_ntoa(caddr.sin_addr));
        handle_request(cfd, caddr);
    }
}