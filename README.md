# WinHTTPD - [darkhttpd](https://unix4lyfe.org/darkhttpd/) ported to Windows 

Few points first:
* _darkhttpd_ ver = 1.12 (newest)
* Why _**win**-httpd_ and not _**dark**-httpd_? you may ask
    - Well, ever glanced over into the ```<windows.h>``` library? Windows is by definition **dark**, so you'll suddenly realize that the name actually still is **darkhttpd** and your eyes are playing tricks on you.
* It's ported to be compilable with MSVC compiler, I do not know what weird stuff can happen if you try to compile this with MinGW or Cygwin.
* You can see the whole current diff with darkhttpd [here](util/portdiff.md).

Usage
```batch
winhttpd.exe [options]
```

Right now, you can't use options --chroot, --deamon, --uid, --gid and --pidfile. Some of them for obvious reasons, other are coming soon.
