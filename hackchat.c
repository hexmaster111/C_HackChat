#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT (8082)

#define HTTP_200_OK "HTTP/1.1 200 OK\r\n"
#define HTTP_404_ERR "HTTP/1.1 404 PAGE NOT FOUND\r\n"
#define CONTENT_TEXT_HTML "Content-Type: text/html\r\n"

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
    (Slice) { .buf = CLIT, .len = sizeof(CLIT) / sizeof(CLIT[0]) }

// non-zero to be not match  ... tbh idk how memcmps output works, also we just match the parts
// of the shortest string, from the from
int slice_cmp(Slice a, Slice b) { return memcmp(a.buf, b.buf, a.len < b.len ? a.len : b.len); }
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

int WriteDateTimeSkyTime(int fd)
{
    time_t now;
    time(&now);

    // Convert to local time
    struct tm *local = localtime(&now);

    // Format and print the date and time
    char time_buff[100];
    strftime(time_buff, sizeof(time_buff), "This %B the %d Day %A at the %l%p", local);

#define datetime_html HTTP_200_OK CONTENT_TEXT_HTML \
    "\r\n<!DOCTYPE html>\r\n"                       \
    "<html>\r\n"                                    \
    "<head></head>\r\n"                             \
    "<body>\r\n"                                    \
    "%s\r\n"                                        \
    "</body>\r\n"                                   \
    "</html>\r\n\r\n"

    char outbuf[1024] = {0};

    sprintf(outbuf, datetime_html, time_buff);

    return WriteBuffer(fd, outbuf, strlen(outbuf));
#undef datetime_html
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




void Route(
    int fd,
    Slice request,
    Slice method,
    Slice route,
    Slice body,
    int url_argc,
    SlicePair url_args[url_argc])
{

    printf(SLICE_FMT "\n", SLICE_PNT(body));

    if (slice_cmp(SLICE("GET"), method) == 0 && slice_cmp(SLICE("/"), route) == 0)
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

void handle_request(int fd)
{
    char buffer[1024] = {0};
    SlicePair args[128] = {0};

    // i think the first word is always the method, and then the route upto the next space?
    int r = read(fd, buffer, sizeof(buffer));
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
          argc, args);
}

int main(int argc, char *argv[])
{
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

        puts(inet_ntoa(caddr.sin_addr));
        handle_request(cfd);
    }
}