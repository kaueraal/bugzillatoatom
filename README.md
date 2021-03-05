# bugzillatoatom

bugzillatoatom is an open source web application able to convert Bugzilla bugs into an Atom feed.

It allows tracking bugs via your favorite feed reader, without registering at every other Bugzilla bug tracker.
bugzillatoatom is ready to use, just download and run it.
It includes a basic web user interface at port 33916, where you simply can paste your Bugzilla bug url and get the Atom feed back.


## Features

Besides a basic user interface and the conversion of Bugzilla bugs into an Atom feed bugzillatoatom includes several safeguards, as bugzillatoatom basically allows arbitrary http requests.
bugzillatoatom can and does
* limit the number of requests per second
* limit the maximal size read of the remote target
* requires the string "bugzilla" in the first 1024 bytes of a bugzilla bug response
* block requests to given IPs and Networks. You probably want to exclude your local ones, as bugzillatoatom would allow an outsider to request information of the local network.

bugzillatoatom also doesn't download attachments.
The respective links in the Atom feed point to the original data on the Bugzilla server.

Additionally bugzillatoatom is fully IPv6 ready.
This also means you might need to block IPv6 networks as well.

Nevertheless you probably want to set bugzillatoatom behind a caching http proxy to reduce the number of requests.


## Requirements and Building the Application

You need a somewhat recent version of Go.
After you installed Go, a 
```
go get https://bugzillatoatom.affine.space/
```
should suffice.
Go handles the few external dependencies and compiles the application for you.
Afterwards you should find the executable in `$GOPATH/bin/`.


## Command Line Flags
```
Usage of ./bugzillatoatom:
  -b value
      IP or network in CIDR format to block. If a host is available under any blocked IP it will be blocked. Can be given multiple times.
  You probably want to exclude localhost or local networks both on IPv4 and IPv6. These are blocked by default unless you give -nolocalblock.
  -nolocalblock
      Disables default blocking of local networks and IPs. If this flag is given you can add those again via -b.
  This includes all IPs and networks of local interfaces and the networks 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7, fe80::/10, fec0::/10.
  -p uint
      Port to bind to. (default 33916)
  -persecond int
      Maximum number of requests to another server per second. Set to -1 to disable. (default 5)
  -requestsize uint
      Maximum number of bytes to read during a request to another server. (default 1048576)
  -version
      Print the current version and exit.
```