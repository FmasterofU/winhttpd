```diff
diff --git a/winhttpd.c b/winhttpd.c
index 836743b..86bf205 100644
--- a/winhttpd.c
+++ b/winhttpd.c
@@ -1,3 +1,30 @@
+//MIT License
+//
+//WinHTTPD - a port of darkhttpd for Windows OS
+//https://opensource.ieee.org/igorsikuljak/winhttpd
+//
+//Copyright(c) 2020 Igor Šikuljak <igorsikuljak@ieee.org>
+//
+//Permission is hereby granted, free of charge, to any person obtaining a copy
+//of this softwareand associated documentation files(the "Software"), to deal
+//in the Software without restriction, including without limitation the rights
+//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
+//copies of the Software, and to permit persons to whom the Software is
+//furnished to do so, subject to the following conditions :
+//
+//The above copyright noticeand this permission notice shall be included in all
+//copies or substantial portions of the Software.
+//
+//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
+//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
+//SOFTWARE.
+
+
+
 /* darkhttpd - a simple, single-threaded, static content webserver.
  * https://unix4lyfe.org/darkhttpd/
  * Copyright (c) 2003-2018 Emil Mikulic <emikulic@gmail.com>
@@ -17,9 +44,12 @@
  * PERFORMANCE OF THIS SOFTWARE.
  */
 
+#define _CRT_SECURE_NO_WARNINGS
+#define _WINSOCK_DEPRECATED_NO_WARNINGS
+
 static const char
-pkgname[] = "darkhttpd/1.12.from.git",
-copyright[] = "copyright (c) 2003-2018 Emil Mikulic";
+pkgname[] = "WinHTTPD",
+copyright[] = "Copyright(c) 2020 Igor Sikuljak <igorsikuljak@ieee.org>";
 
 /* Possible build options: -DDEBUG -DNO_IPV6 */
 
@@ -29,7 +59,7 @@ copyright[] = "copyright (c) 2003-2018 Emil Mikulic";
 
 #ifndef DEBUG
 # define NDEBUG
-static const int debug = 0;
+static const int debug = 1;
 #else
 static const int debug = 1;
 #endif
@@ -44,31 +74,76 @@ static const int debug = 1;
 # include <sys/sendfile.h>
 #endif
 
-#include <sys/time.h>
-#include <sys/types.h>
-#include <sys/socket.h>
+//#include <sys/time.h>
+#include <sys\types.h>
+//include <sys/socket.h>
 #include <sys/stat.h>
-#include <sys/resource.h>
-#include <sys/wait.h>
-#include <sys/param.h>
-#include <netinet/in.h>
-#include <netinet/tcp.h>
-#include <arpa/inet.h>
+//#include <sys/resource.h>
+//#include <sys/wait.h>
+//#include <sys/param.h>
+//#include <netinet/in.h>
+//#include <netinet/tcp.h>
+//#include <arpa/inet.h>
 #include <assert.h>
 #include <ctype.h>
-#include <dirent.h>
+//#include <dirent.h>
+#include "include\dirent.h"
 #include <errno.h>
 #include <fcntl.h>
-#include <grp.h>
+//#include <grp.h>
 #include <limits.h>
-#include <pwd.h>
+//#include <pwd.h>
 #include <signal.h>
 #include <stdarg.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
-#include <unistd.h>
+//#include <unistd.h>
+
+
+#include <winsock2.h>
+#include <wchar.h>
+#include <stdint.h>
+#include <ws2tcpip.h>
+#include <fcntl.h>
+#include <stddef.h>
+#include <io.h>
+#include <errno.h>
+#include <stdarg.h>
+
+#pragma comment(lib, "ws2_32.lib")
+
+typedef int gid_t;
+typedef int uid_t;
+typedef int pid_t;
+typedef unsigned long in_addr_t;
+typedef long int ssize_t;
+
+#define close(fd) _close(fd)
+#define open(path, mode) _open(path, mode)
+#define read(path, buff, size) _read(path, buff, size)
+#define lseek(path, offset, mode) _lseek(path, offset, mode)
+#define strcasecmp(first, second) _stricmp(first, second)
+#define vscprintf _vscprintf
+
+int vasprintf(char** strp, const char* format, va_list ap)
+{
+    int len = vscprintf(format, ap);
+    if (len == -1)
+        return -1;
+    char* str = (char*)malloc((size_t)len + 1);
+    if (!str)
+        return -1;
+    int retval = vsnprintf(str, (size_t) len + 1, format, ap);
+    if (retval == -1) {
+        free(str);
+        return -1;
+    }
+    *strp = str;
+    return retval;
+}
+
 
 #ifdef __sun__
 # ifndef INADDR_NONE
@@ -342,6 +417,13 @@ static void xclose(const int fd) {
         err(1, "close()");
 }
 
+// closesocket() dies on error
+static void xclosesock(const int fd) {
+    if (closesocket(fd) != 0) {
+        err(1, "closesocket()");
+    }
+}
+
 /* malloc that dies if it can't allocate. */
 static void* xmalloc(const size_t size) {
     void* ptr = malloc(size);
@@ -459,13 +541,17 @@ static void appendf(struct apbuf* buf, const char* format, ...) {
 
 /* Make the specified socket non-blocking. */
 static void nonblock_socket(const int sock) {
-    int flags = fcntl(sock, F_GETFL);
+    //int flags = fcntl(sock, F_GETFL);
+    //
+
+    //if (flags == -1)
+    //    err(1, "fcntl(F_GETFL)");
+    //flags |= O_NONBLOCK;
+    //if (fcntl(sock, F_SETFL, flags) == -1)
+    //    err(1, "fcntl() to set O_NONBLOCK");
+    u_long nonblocking_enabled = TRUE;
+    int flags = ioctlsocket(sock, FIONBIO, &nonblocking_enabled);
 
-    if (flags == -1)
-        err(1, "fcntl(F_GETFL)");
-    flags |= O_NONBLOCK;
-    if (fcntl(sock, F_SETFL, flags) == -1)
-        err(1, "fcntl() to set O_NONBLOCK");
 }
 
 /* Split string out of src with range [left:right-1] */
@@ -805,7 +891,7 @@ static void init_sockin(void) {
     /* reuse address */
     sockopt = 1;
     if (setsockopt(sockin, SOL_SOCKET, SO_REUSEADDR,
-        &sockopt, sizeof(sockopt)) == -1)
+        (char*) &sockopt, sizeof(sockopt)) == -1)
         err(1, "setsockopt(SO_REUSEADDR)");
 
 #if 0
@@ -888,10 +974,10 @@ static void usage(const char* argv0) {
         "\t\tSpecifies how many concurrent connections to accept.\n\n");
     printf("\t--log filename (default: stdout)\n"
         "\t\tSpecifies which file to append the request log to.\n\n");
-    printf("\t--chroot (default: don't chroot)\n"
-        "\t\tLocks server into wwwroot directory for added security.\n\n");
-    printf("\t--daemon (default: don't daemonize)\n"
-        "\t\tDetach from the controlling terminal and run in the background.\n\n");
+    //printf("\t--chroot (default: don't chroot)\n"
+    //    "\t\tLocks server into wwwroot directory for added security.\n\n");
+    //printf("\t--daemon (default: don't daemonize)\n"
+    //    "\t\tDetach from the controlling terminal and run in the background.\n\n");
     printf("\t--index filename (default: %s)\n"
         "\t\tDefault file to serve when a directory is requested.\n\n",
         index_name);
@@ -902,12 +988,12 @@ static void usage(const char* argv0) {
     printf("\t--default-mimetype string (optional, default: %s)\n"
         "\t\tFiles with unknown extensions are served as this mimetype.\n\n",
         octet_stream);
-    printf("\t--uid uid/uname, --gid gid/gname (default: don't privdrop)\n"
-        "\t\tDrops privileges to given uid:gid after initialization.\n\n");
-    printf("\t--pidfile filename (default: no pidfile)\n"
-        "\t\tWrite PID to the specified file.  Note that if you are\n"
-        "\t\tusing --chroot, then the pidfile must be relative to,\n"
-        "\t\tand inside the wwwroot.\n\n");
+    //printf("\t--uid uid/uname, --gid gid/gname (default: don't privdrop)\n"
+    //    "\t\tDrops privileges to given uid:gid after initialization.\n\n");
+    //printf("\t--pidfile filename (default: no pidfile)\n"
+    //    "\t\tWrite PID to the specified file.  Note that if you are\n"
+    //    "\t\tusing --chroot, then the pidfile must be relative to,\n"
+    //    "\t\tand inside the wwwroot.\n\n");
     printf("\t--no-keepalive\n"
         "\t\tDisables HTTP Keep-Alive functionality.\n\n");
 #ifdef __FreeBSD__
@@ -976,7 +1062,7 @@ static void parse_commandline(const int argc, char* argv[]) {
         exit(EXIT_SUCCESS);
     }
 
-    if (getuid() == 0)
+    //if (getuid() == 0)
         bindport = 80;
 
     wwwroot = xstrdup(argv[1]);
@@ -1008,12 +1094,12 @@ static void parse_commandline(const int argc, char* argv[]) {
                 errx(1, "missing filename after --log");
             logfile_name = argv[i];
         }
-        else if (strcmp(argv[i], "--chroot") == 0) {
-            want_chroot = 1;
-        }
-        else if (strcmp(argv[i], "--daemon") == 0) {
-            want_daemon = 1;
-        }
+        //else if (strcmp(argv[i], "--chroot") == 0) {
+        //    want_chroot = 1;
+        //}
+        //else if (strcmp(argv[i], "--daemon") == 0) {
+        //    want_daemon = 1;
+        //}
         else if (strcmp(argv[i], "--index") == 0) {
             if (++i >= argc)
                 errx(1, "missing filename after --index");
@@ -1032,36 +1118,36 @@ static void parse_commandline(const int argc, char* argv[]) {
                 errx(1, "missing string after --default-mimetype");
             default_mimetype = argv[i];
         }
-        else if (strcmp(argv[i], "--uid") == 0) {
-            struct passwd* p;
-            if (++i >= argc)
-                errx(1, "missing uid after --uid");
-            p = getpwnam(argv[i]);
-            if (!p) {
-                p = getpwuid((uid_t)xstr_to_num(argv[i]));
-            }
-            if (!p)
-                errx(1, "no such uid: `%s'", argv[i]);
-            drop_uid = p->pw_uid;
-        }
-        else if (strcmp(argv[i], "--gid") == 0) {
-            struct group* g;
-            if (++i >= argc)
-                errx(1, "missing gid after --gid");
-            g = getgrnam(argv[i]);
-            if (!g) {
-                g = getgrgid((gid_t)xstr_to_num(argv[i]));
-            }
-            if (!g) {
-                errx(1, "no such gid: `%s'", argv[i]);
-            }
-            drop_gid = g->gr_gid;
-        }
-        else if (strcmp(argv[i], "--pidfile") == 0) {
-            if (++i >= argc)
-                errx(1, "missing filename after --pidfile");
-            pidfile_name = argv[i];
-        }
+        //else if (strcmp(argv[i], "--uid") == 0) {
+        //    struct passwd* p;
+        //    if (++i >= argc)
+        //        errx(1, "missing uid after --uid");
+        //    p = getpwnam(argv[i]);
+        //    if (!p) {
+        //        p = getpwuid((uid_t)xstr_to_num(argv[i]));
+        //    }
+        //    if (!p)
+        //        errx(1, "no such uid: `%s'", argv[i]);
+        //    drop_uid = p->pw_uid;
+        //}
+        //else if (strcmp(argv[i], "--gid") == 0) {
+        //    struct group* g;
+        //    if (++i >= argc)
+        //        errx(1, "missing gid after --gid");
+        //    g = getgrnam(argv[i]);
+        //    if (!g) {
+        //        g = getgrgid((gid_t)xstr_to_num(argv[i]));
+        //    }
+        //    if (!g) {
+        //        errx(1, "no such gid: `%s'", argv[i]);
+        //    }
+        //    drop_gid = g->gr_gid;
+        //}
+        //else if (strcmp(argv[i], "--pidfile") == 0) {
+        //    if (++i >= argc)
+        //        errx(1, "missing filename after --pidfile");
+        //    pidfile_name = argv[i];
+        //}
         else if (strcmp(argv[i], "--no-keepalive") == 0) {
             want_keepalive = 0;
         }
@@ -1279,7 +1365,7 @@ static void log_connection(const struct connection* conn) {
 static void free_connection(struct connection* conn) {
     if (debug) printf("free_connection(%d)\n", conn->socket);
     log_connection(conn);
-    if (conn->socket != -1) xclose(conn->socket);
+    if (conn->socket != -1) xclosesock(conn->socket);
     if (conn->request != NULL) free(conn->request);
     if (conn->method != NULL) free(conn->method);
     if (conn->url != NULL) free(conn->url);
@@ -1860,6 +1946,44 @@ static void process_get(struct connection* conn) {
     /* work out path of file being requested */
     decoded_url = urldecode(conn->url);
 
+    // create a windows type equivalent for decoded_url
+    int iter, du_len = strlen(decoded_url);
+    char* decoded_url_win = xmalloc(du_len + 2);
+    for (iter = 0; iter < du_len; iter++)
+        if (decoded_url[iter] == '/')
+            decoded_url_win[iter] = '\\';
+        else decoded_url_win[iter] = decoded_url[iter];
+    decoded_url_win[du_len] = '\0';
+    if (decoded_url_win[du_len - 1] == '\\')
+        decoded_url_win[du_len - 1] = '\0';
+
+    struct stat path_stat;
+    xasprintf(&target, "%s%s", wwwroot, decoded_url_win);
+    stat(target, &path_stat);
+    if ((path_stat.st_mode & (_S_IFDIR | _S_IREAD)) == (_S_IFDIR | _S_IREAD)) {
+        if (decoded_url[du_len - 1] != '/') {
+            redirect(conn, "%s/", decoded_url);
+            free(decoded_url);
+            free(decoded_url_win);
+            free(target);
+            return;
+        }
+        decoded_url_win[du_len - 1] = '\\';
+        decoded_url_win[du_len] = '\0';
+    }
+    else if ((path_stat.st_mode & (_S_IFREG | _S_IREAD)) == (_S_IFREG | _S_IREAD)) {
+        if (decoded_url[du_len - 1] == '/') {
+            decoded_url[du_len - 1] = '\0';
+            redirect(conn, "%s", decoded_url);
+            free(decoded_url);
+            free(decoded_url_win);
+            free(target);
+            return;
+        }
+        decoded_url_win[du_len] = '\0';
+    }
+    free(target);
+
     /* make sure it's safe */
     if (make_safe_url(decoded_url) == NULL) {
         default_reply(conn, 400, "Bad Request",
@@ -1894,12 +2018,13 @@ static void process_get(struct connection* conn) {
     }
 
     /* does it end in a slash? serve up url/index_name */
-    if (decoded_url[strlen(decoded_url) - 1] == '/') {
-        xasprintf(&target, "%s%s%s", wwwroot, decoded_url, index_name);
+    if (decoded_url_win[strlen(decoded_url_win) - 1] == '\\') {
+        xasprintf(&target, "%s%s%s", wwwroot, decoded_url_win, index_name);
         if (!file_exists(target)) {
             free(target);
             if (no_listing) {
                 free(decoded_url);
+                free(decoded_url_win);
                 /* Return 404 instead of 403 to make --no-listing
                  * indistinguishable from the directory not existing.
                  * i.e.: Don't leak information.
@@ -1912,22 +2037,26 @@ static void process_get(struct connection* conn) {
             generate_dir_listing(conn, target);
             free(target);
             free(decoded_url);
+            free(decoded_url_win);
             return;
         }
         mimetype = url_content_type(index_name);
     }
     else {
         /* points to a file */
-        xasprintf(&target, "%s%s", wwwroot, decoded_url);
+        xasprintf(&target, "%s%s", wwwroot, decoded_url_win);
         mimetype = url_content_type(decoded_url);
     }
     free(decoded_url);
+    free(decoded_url_win);
     if (debug)
         printf("url=\"%s\", target=\"%s\", content-type=\"%s\"\n",
             conn->url, target, mimetype);
 
     /* open file */
-    conn->reply_fd = open(target, O_RDONLY | O_NONBLOCK);
+    /*conn->reply_fd = open(target, O_RDONLY | O_NONBLOCK);*/
+    // lets pray for this, win does not have non blockking supported in open()
+    conn->reply_fd = open(target, _O_BINARY | _O_RDONLY);
     free(target);
 
     if (conn->reply_fd == -1) {
@@ -2115,11 +2244,15 @@ static void process_request(struct connection* conn) {
 
 /* Receiving request. */
 static void poll_recv_request(struct connection* conn) {
-    char buf[1 << 15];
+    char * buf = (char*)malloc(1 << 15);
+    if (buf == NULL) {
+        printf("Out of memory!");
+        exit(-1);
+    }
     ssize_t recvd;
 
     assert(conn->state == RECV_REQUEST);
-    recvd = recv(conn->socket, buf, sizeof(buf), 0);
+    recvd = recv(conn->socket, buf, 1 << 15, 0);
     if (debug)
         printf("poll_recv_request(%d) got %d bytes\n",
             conn->socket, (int)recvd);
@@ -2127,6 +2260,7 @@ static void poll_recv_request(struct connection* conn) {
         if (recvd == -1) {
             if (errno == EAGAIN) {
                 if (debug) printf("poll_recv_request would have blocked\n");
+                free(buf);
                 return;
             }
             if (debug) printf("recv(%d) error: %s\n",
@@ -2134,6 +2268,7 @@ static void poll_recv_request(struct connection* conn) {
         }
         conn->conn_close = 1;
         conn->state = DONE;
+        free(buf);
         return;
     }
     conn->last_active = now;
@@ -2167,6 +2302,7 @@ static void poll_recv_request(struct connection* conn) {
      */
     if (conn->state == SEND_HEADER)
         poll_send_header(conn);
+    free(buf);
 }
 
 /* Sending header.  Assumes conn->header is not NULL. */
@@ -2251,8 +2387,12 @@ static ssize_t send_from_file(const int s, const int fd,
 # ifndef min
 #  define min(a,b) ( ((a)<(b)) ? (a) : (b) )
 # endif
-    char buf[1 << 15];
-    size_t amount = min(sizeof(buf), size);
+    char * buf = (char*)malloc(1 << 15);
+    if (buf == NULL) {
+        printf("Out of memory!");
+        exit(-1);
+    }
+    size_t amount = min(1 << 15, size);
     ssize_t numread;
 
     if (lseek(fd, ofs, SEEK_SET) == -1)
@@ -2260,10 +2400,12 @@ static ssize_t send_from_file(const int s, const int fd,
     numread = read(fd, buf, amount);
     if (numread == 0) {
         fprintf(stderr, "premature eof on fd %d\n", fd);
+        free(buf);
         return -1;
     }
     else if (numread == -1) {
         fprintf(stderr, "error reading on fd %d: %s", fd, strerror(errno));
+        free(buf);
         return -1;
     }
     else if ((size_t)numread != amount) {
@@ -2271,8 +2413,12 @@ static ssize_t send_from_file(const int s, const int fd,
             numread, amount, fd);
         return -1;
     }
-    else
-        return send(s, buf, amount, 0);
+    else {
+        int ret = send(s, buf, amount, 0); 
+        free(buf);
+        printf("sending %d bytes", ret);
+        return ret;
+    }
 #endif
 #endif
 }
@@ -2295,7 +2441,7 @@ static void poll_send_reply(struct connection* conn)
         assert(conn->reply_length >= conn->reply_sent);
         sent = send_from_file(conn->socket, conn->reply_fd,
             conn->reply_start + conn->reply_sent,
-            (size_t)(conn->reply_length - conn->reply_sent));
+            (size_t) conn->reply_length - conn->reply_sent);
         if (debug && (sent < 1))
             printf("send_from_file returned %lld (errno=%d %s)\n",
                 (long long)sent, errno, strerror(errno));
@@ -2343,7 +2489,7 @@ static void httpd_poll(void) {
     int max_fd, select_ret;
     struct connection* conn, * next;
     int bother_with_timeout = 0;
-    struct timeval timeout, t0, t1;
+    struct timeval timeout;// , t0, t1;
 
     timeout.tv_sec = timeout_secs;
     timeout.tv_usec = 0;
@@ -2378,11 +2524,11 @@ static void httpd_poll(void) {
 #undef MAX_FD_SET
 
     /* -select- */
-    if (debug) {
-        printf("select() with max_fd %d timeout %d\n",
-            max_fd, bother_with_timeout ? (int)timeout.tv_sec : 0);
-        gettimeofday(&t0, NULL);
-    }
+    //if (debug) {
+    //    printf("select() with max_fd %d timeout %d\n",
+    //        max_fd, bother_with_timeout ? (int)timeout.tv_sec : 0);
+    //    gettimeofday(&t0, NULL);
+    //}
     select_ret = select(max_fd + 1, &recv_set, &send_set, NULL,
         (bother_with_timeout) ? &timeout : NULL);
     if (select_ret == 0) {
@@ -2395,18 +2541,18 @@ static void httpd_poll(void) {
         else
             err(1, "select() failed");
     }
-    if (debug) {
-        long long sec, usec;
-        gettimeofday(&t1, NULL);
-        sec = t1.tv_sec - t0.tv_sec;
-        usec = t1.tv_usec - t0.tv_usec;
-        if (usec < 0) {
-            usec += 1000000;
-            sec--;
-        }
-        printf("select() returned %d after %lld.%06lld secs\n",
-            select_ret, sec, usec);
-    }
+    //if (debug) {
+    //    long long sec, usec;
+    //    gettimeofday(&t1, NULL);
+    //    sec = t1.tv_sec - t0.tv_sec;
+    //    usec = t1.tv_usec - t0.tv_usec;
+    //    if (usec < 0) {
+    //        usec += 1000000;
+    //        sec--;
+    //    }
+    //    printf("select() returned %d after %lld.%06lld secs\n",
+    //        select_ret, sec, usec);
+    //}
 
     /* update time */
     now = time(NULL);
@@ -2454,135 +2600,137 @@ static void httpd_poll(void) {
     }
 }
 
-/* Daemonize helpers. */
-#define PATH_DEVNULL "/dev/null"
-static int lifeline[2] = { -1, -1 };
-static int fd_null = -1;
-
-static void daemonize_start(void) {
-    pid_t f;
-
-    if (pipe(lifeline) == -1)
-        err(1, "pipe(lifeline)");
-
-    fd_null = open(PATH_DEVNULL, O_RDWR, 0);
-    if (fd_null == -1)
-        err(1, "open(" PATH_DEVNULL ")");
-
-    f = fork();
-    if (f == -1)
-        err(1, "fork");
-    else if (f != 0) {
-        /* parent: wait for child */
-        char tmp[1];
-        int status;
-        pid_t w;
-
-        if (close(lifeline[1]) == -1)
-            warn("close lifeline in parent");
-        if (read(lifeline[0], tmp, sizeof(tmp)) == -1)
-            warn("read lifeline in parent");
-        w = waitpid(f, &status, WNOHANG);
-        if (w == -1)
-            err(1, "waitpid");
-        else if (w == 0)
-            /* child is running happily */
-            exit(EXIT_SUCCESS);
-        else
-            /* child init failed, pass on its exit status */
-            exit(WEXITSTATUS(status));
-    }
-    /* else we are the child: continue initializing */
-}
-
-static void daemonize_finish(void) {
-    if (fd_null == -1)
-        return; /* didn't daemonize_start() so we're not daemonizing */
-
-    if (setsid() == -1)
-        err(1, "setsid");
-    if (close(lifeline[0]) == -1)
-        warn("close read end of lifeline in child");
-    if (close(lifeline[1]) == -1)
-        warn("couldn't cut the lifeline");
-
-    /* close all our std fds */
-    if (dup2(fd_null, STDIN_FILENO) == -1)
-        warn("dup2(stdin)");
-    if (dup2(fd_null, STDOUT_FILENO) == -1)
-        warn("dup2(stdout)");
-    if (dup2(fd_null, STDERR_FILENO) == -1)
-        warn("dup2(stderr)");
-    if (fd_null > 2)
-        close(fd_null);
-}
+///* Daemonize helpers. */
+//#define PATH_DEVNULL "/dev/null"
+//static int lifeline[2] = { -1, -1 };
+//static int fd_null = -1;
+
+//static void daemonize_start(void) {
+    //pid_t f;
+
+    //if (pipe(lifeline) == -1)
+    //    err(1, "pipe(lifeline)");
+
+    //fd_null = open(PATH_DEVNULL, O_RDWR, 0);
+    //if (fd_null == -1)
+    //    err(1, "open(" PATH_DEVNULL ")");
+
+    //f = fork();
+    //if (f == -1)
+    //    err(1, "fork");
+    //else if (f != 0) {
+    //    /* parent: wait for child */
+    //    char tmp[1];
+    //    int status;
+    //    pid_t w;
+
+    //    if (close(lifeline[1]) == -1)
+    //        warn("close lifeline in parent");
+    //    if (read(lifeline[0], tmp, sizeof(tmp)) == -1)
+    //        warn("read lifeline in parent");
+    //    w = waitpid(f, &status, WNOHANG);
+    //    if (w == -1)
+    //        err(1, "waitpid");
+    //    else if (w == 0)
+    //        /* child is running happily */
+    //        exit(EXIT_SUCCESS);
+    //    else
+    //        /* child init failed, pass on its exit status */
+    //        exit(WEXITSTATUS(status));
+    //}
+    ///* else we are the child: continue initializing */
+//}
+
+//static void daemonize_finish(void) {
+    //if (fd_null == -1)
+    //    return; /* didn't daemonize_start() so we're not daemonizing */
+
+    //if (setsid() == -1)
+    //    err(1, "setsid");
+    //if (close(lifeline[0]) == -1)
+    //    warn("close read end of lifeline in child");
+    //if (close(lifeline[1]) == -1)
+    //    warn("couldn't cut the lifeline");
+
+    ///* close all our std fds */
+    //if (dup2(fd_null, STDIN_FILENO) == -1)
+    //    warn("dup2(stdin)");
+    //if (dup2(fd_null, STDOUT_FILENO) == -1)
+    //    warn("dup2(stdout)");
+    //if (dup2(fd_null, STDERR_FILENO) == -1)
+    //    warn("dup2(stderr)");
+    //if (fd_null > 2)
+    //    close(fd_null);
+//}
 
 /* [->] pidfile helpers, based on FreeBSD src/lib/libutil/pidfile.c,v 1.3
  * Original was copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
  */
-static int pidfile_fd = -1;
-#define PIDFILE_MODE 0600
-
-static void pidfile_remove(void) {
-    if (unlink(pidfile_name) == -1)
-        err(1, "unlink(pidfile) failed");
-    /* if (flock(pidfile_fd, LOCK_UN) == -1)
-           err(1, "unlock(pidfile) failed"); */
-    xclose(pidfile_fd);
-    pidfile_fd = -1;
-}
-
-static int pidfile_read(void) {
-    char buf[16];
-    int fd, i;
-    long long pid;
-
-    fd = open(pidfile_name, O_RDONLY);
-    if (fd == -1)
-        err(1, " after create failed");
-
-    i = (int)read(fd, buf, sizeof(buf) - 1);
-    if (i == -1)
-        err(1, "read from pidfile failed");
-    xclose(fd);
-    buf[i] = '\0';
-
-    if (!str_to_num(buf, &pid)) {
-        err(1, "invalid pidfile contents: \"%s\"", buf);
-    }
-    return (int)pid;
-}
-
-static void pidfile_create(void) {
-    int error, fd;
-    char pidstr[16];
-
-    /* Open the PID file and obtain exclusive lock. */
-    fd = open(pidfile_name,
-        O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK, PIDFILE_MODE);
-    if (fd == -1) {
-        if ((errno == EWOULDBLOCK) || (errno == EEXIST))
-            errx(1, "daemon already running with PID %d", pidfile_read());
-        else
-            err(1, "can't create pidfile %s", pidfile_name);
-    }
-    pidfile_fd = fd;
-
-    if (ftruncate(fd, 0) == -1) {
-        error = errno;
-        pidfile_remove();
-        errno = error;
-        err(1, "ftruncate() failed");
-    }
-
-    snprintf(pidstr, sizeof(pidstr), "%d", (int)getpid());
-    if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
-        error = errno;
-        pidfile_remove();
-        errno = error;
-        err(1, "pwrite() failed");
-    }
-}
+//static int pidfile_fd = -1;
+//#define PIDFILE_MODE 0600
+
+//static void pidfile_remove(void) {
+    //if (unlink(pidfile_name) == -1)
+    //    err(1, "unlink(pidfile) failed");
+    ///* if (flock(pidfile_fd, LOCK_UN) == -1)
+    //       err(1, "unlock(pidfile) failed"); */
+    //xclose(pidfile_fd);
+    //pidfile_fd = -1;
+//}
+
+//static int pidfile_read(void) {
+    //char buf[16];
+    //int fd, i;
+    //long long pid;
+
+    //fd = open(pidfile_name, O_RDONLY);
+    //if (fd == -1)
+    //    err(1, " after create failed");
+
+    //i = (int)read(fd, buf, sizeof(buf) - 1);
+    //if (i == -1)
+    //    err(1, "read from pidfile failed");
+    //xclose(fd);
+    //buf[i] = '\0';
+
+    //if (!str_to_num(buf, &pid)) {
+    //    err(1, "invalid pidfile contents: \"%s\"", buf);
+    //}
+    //return (int)pid;
+//}
+
+//static void pidfile_create(void) {
+    //int error, fd;
+    //char pidstr[16];
+
+    ///* Open the PID file and obtain exclusive lock. */
+    ////fd = open(pidfile_name,
+    ////    O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC | O_NONBLOCK, PIDFILE_MODE);
+    //// no nonblocking with open() in win
+    //fd = open(pidfile_name, O_WRONLY | O_CREAT | O_EXLOCK | O_TRUNC, PIDFILE_MODE);
+    //if (fd == -1) {
+    //    if ((errno == EWOULDBLOCK) || (errno == EEXIST))
+    //        errx(1, "daemon already running with PID %d", pidfile_read());
+    //    else
+    //        err(1, "can't create pidfile %s", pidfile_name);
+    //}
+    //pidfile_fd = fd;
+
+    //if (ftruncate(fd, 0) == -1) {
+    //    error = errno;
+    //    pidfile_remove();
+    //    errno = error;
+    //    err(1, "ftruncate() failed");
+    //}
+
+    //snprintf(pidstr, sizeof(pidstr), "%d", (int)getpid());
+    //if (pwrite(fd, pidstr, strlen(pidstr), 0) != (ssize_t)strlen(pidstr)) {
+    //    error = errno;
+    //    pidfile_remove();
+    //    errno = error;
+    //    err(1, "pwrite() failed");
+    //}
+//}
 /* [<-] end of pidfile helpers. */
 
 /* Close all sockets and FILEs and exit. */
@@ -2604,6 +2752,27 @@ int main(int argc, char** argv) {
         xasprintf(&server_hdr, "Server: %s\r\n", pkgname);
     else
         server_hdr = xstrdup("");
+
+
+    // winsock startup code
+    WORD wVersionRequested;
+    WSADATA wsaData;
+    int code;
+
+    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
+    wVersionRequested = MAKEWORD(2, 2);
+
+    code = WSAStartup(wVersionRequested, &wsaData);
+    if (code != 0) {
+        /* Tell the user that we could not find a usable */
+        /* Winsock DLL.                                  */
+        printf("WSAStartup failed with error: %d\n", code);
+        return 1;
+    }
+
+    // end winsock startup code
+
+
     init_sockin();
 
     /* open logfile */
@@ -2615,54 +2784,63 @@ int main(int argc, char** argv) {
             err(1, "opening logfile: fopen(\"%s\")", logfile_name);
     }
 
-    if (want_daemon)
-        daemonize_start();
+    //if (want_daemon)
+    //    daemonize_start();
 
     /* signals */
-    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
-        err(1, "signal(ignore SIGPIPE)");
+    //if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
+    //    err(1, "signal(ignore SIGPIPE)");
     if (signal(SIGINT, stop_running) == SIG_ERR)
         err(1, "signal(SIGINT)");
     if (signal(SIGTERM, stop_running) == SIG_ERR)
         err(1, "signal(SIGTERM)");
 
-    /* security */
-    if (want_chroot) {
-        tzset(); /* read /etc/localtime before we chroot */
-        if (chdir(wwwroot) == -1)
-            err(1, "chdir(%s)", wwwroot);
-        if (chroot(wwwroot) == -1)
-            err(1, "chroot(%s)", wwwroot);
-        printf("chrooted to `%s'\n", wwwroot);
-        wwwroot[0] = '\0'; /* empty string */
-    }
-    if (drop_gid != INVALID_GID) {
-        gid_t list[1];
-        list[0] = drop_gid;
-        if (setgroups(1, list) == -1)
-            err(1, "setgroups([%d])", (int)drop_gid);
-        if (setgid(drop_gid) == -1)
-            err(1, "setgid(%d)", (int)drop_gid);
-        printf("set gid to %d\n", (int)drop_gid);
-    }
-    if (drop_uid != INVALID_UID) {
-        if (setuid(drop_uid) == -1)
-            err(1, "setuid(%d)", (int)drop_uid);
-        printf("set uid to %d\n", (int)drop_uid);
-    }
-
-    /* create pidfile */
-    if (pidfile_name) pidfile_create();
-
-    if (want_daemon) daemonize_finish();
+    ///* security */
+    //if (want_chroot) {
+    //    tzset(); /* read /etc/localtime before we chroot */
+    //    if (chdir(wwwroot) == -1)
+    //        err(1, "chdir(%s)", wwwroot);
+    //    if (chroot(wwwroot) == -1)
+    //        err(1, "chroot(%s)", wwwroot);
+    //    printf("chrooted to `%s'\n", wwwroot);
+    //    wwwroot[0] = '\0'; /* empty string */
+    //}
+    //if (drop_gid != INVALID_GID) {
+    //    gid_t list[1];
+    //    list[0] = drop_gid;
+    //    if (setgroups(1, list) == -1)
+    //        err(1, "setgroups([%d])", (int)drop_gid);
+    //    if (setgid(drop_gid) == -1)
+    //        err(1, "setgid(%d)", (int)drop_gid);
+    //    printf("set gid to %d\n", (int)drop_gid);
+    //}
+    //if (drop_uid != INVALID_UID) {
+    //    if (setuid(drop_uid) == -1)
+    //        err(1, "setuid(%d)", (int)drop_uid);
+    //    printf("set uid to %d\n", (int)drop_uid);
+    //}
+
+    ///* create pidfile */
+    //if (pidfile_name) pidfile_create();
+
+    //if (want_daemon) daemonize_finish();
 
     /* main loop */
     while (running) httpd_poll();
 
     /* clean exit */
-    xclose(sockin);
+    xclosesock(sockin);
+
+
+    // winsock cleanup call
+
+    WSACleanup();
+
+    // end winsock cleanup call
+
+
     if (logfile != NULL) fclose(logfile);
-    if (pidfile_name) pidfile_remove();
+    //if (pidfile_name) pidfile_remove();
 
     /* close and free connections */
     {
@@ -2690,22 +2868,21 @@ int main(int argc, char** argv) {
         free(server_hdr);
     }
 
-    /* usage stats */
-    {
-        struct rusage r;
-
-        getrusage(RUSAGE_SELF, &r);
-        printf("CPU time used: %u.%02u user, %u.%02u system\n",
-            (unsigned int)r.ru_utime.tv_sec,
-            (unsigned int)(r.ru_utime.tv_usec / 10000),
-            (unsigned int)r.ru_stime.tv_sec,
-            (unsigned int)(r.ru_stime.tv_usec / 10000)
-            );
-        printf("Requests: %llu\n", llu(num_requests));
-        printf("Bytes: %llu in, %llu out\n", llu(total_in), llu(total_out));
-    }
-
+    ///* usage stats */
+    //{
+    //    struct rusage r;
+
+    //    getrusage(RUSAGE_SELF, &r);
+    //    printf("CPU time used: %u.%02u user, %u.%02u system\n",
+    //        (unsigned int)r.ru_utime.tv_sec,
+    //        (unsigned int)(r.ru_utime.tv_usec / 10000),
+    //        (unsigned int)r.ru_stime.tv_sec,
+    //        (unsigned int)(r.ru_stime.tv_usec / 10000)
+    //        );
+    //    printf("Requests: %llu\n", llu(num_requests));
+    //    printf("Bytes: %llu in, %llu out\n", llu(total_in), llu(total_out));
+    //}
     return 0;
 }
 
-/* vim:set ts=4 sw=4 sts=4 expandtab tw=78: */
\ No newline at end of file
+/* vim:set ts=4 sw=4 sts=4 expandtab tw=78: */
```
