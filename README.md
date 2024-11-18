[![C/C++ CI](https://github.com/maroofi/bulkDNS/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/maroofi/bulkDNS/actions/workflows/c-cpp.yml)

### bulkDNS: A fast DNS scanner for large-scale Internet measurement

Using **bulkDNS**, you can scan millions of domain names in a few minutes. The scanner has been designed to be fast with a very small footprint. It also supports customized scan scenarios through Lua scripting. Check our [benchmark](#Benchmark) to compare it with other scanners.

The output of bulkDNS is a detailed JSON structure (example at the end of the page) which can be parsed both by command-line (e.g., by `jq`) or any programming language.

### Menu

* [How to compile bulkDNS](#How-to-compile)
    * [Compile without Lua](#Compile-without-Lua)
    * [Compile with Lua for customized scan scenarios](#Compile-with-Lua-for-customized-scan-scenarios)
* [Benchmark - Comparison of bulkDNS with ZDNS, massDNS](#Benchmark)
* [Supported Resource Records (RRs)](#Supported-Resource-Records)
* [List of Switches](#List-of-Switches)
* [Example Output](#Example-Output)
* [Notes](#Notes)
	* [A note on threads and concurrency](#A-note-on-threads-and-concurrency)
	* [A note on names and conventions](#Names-and-output-convention)
   	* [Hex representation of the output](#Hex-represantaion-of-the-output)
* [Using Lua for customized scan scenario](#Using-Lua-for-customized-scan-scenario)
* [Running bulkDNS in server mode](#Running-bulkDNS-in-server-mode)
* [FAQ](#FAQ)
 	

### How to compile

You have two options to compile bulkDNS. If You just want to use the scanner for scanning resource records like `A`, `AAAA`, `NS`, `MX`, etc, You can compile the scanner without Lua which is very easy. However, if you want to use `--server-mode` option or you have your own scan scenarios in mind that is more complicated than a simple resource record, then you must compile _bulkDNS_ with Lua support. Here is the instruction for both cases:

#### Compile without Lua

This is the first case (just scanning resource records)

You need to have `jansson` and `pthread` installed.

```bash

# first you need to recursively fetch this repository

git clone --recurse-submodules  https://github.com/maroofi/bulkDNS.git

# install the dependencies
sudo apt install libpthread-stubs0-dev libjansson-dev

# and then you can make bulkDNS

cd bulkDNS

make

```

The compiled output is inside the `bin` directory.

#### Compile with Lua for customized scan scenarios

In this case, you need to have `lua5.4`, `pthread` and `jansson` installed. Here is the procedure:
```bash
# install lua binary
sudo apt install lua5.4

# install lua lib
sudo apt install liblua5.4-dev

# install the dependencies
sudo apt install libpthread-stubs0-dev libjansson-dev

# after installing lua, if you run pkg-config like this:
pkg-config --cflags --libs lua5.4
# you should see an output like this:
# -I/usr/include/lua5.4 -llua5.4

# Now clone the repository
git clone --recurse-submodules  https://github.com/maroofi/bulkDNS.git

# and make with the following commands
cd bulkDNS
make with-lua

```
The compiled output is inside the `bin` directory.

In case the `pkg-config` commands gives you a different output for Lua headers and library locations, then 
you must specify the values when running `make` command like this:

```bash
make LUALIB=<your-lua-lib-name> LUAINCDIR=<your-path-to-lua-include-dir> with-lua
```

That's all!

### Benchmark

To compare bulkDNS with ZDNS and massDNS, we use the cheapest Hetzner VPS (CX22), with 2 virtual (Intel) core and 4 GB of RAM and 40 GB of SSD disk space located in Germany with one IPv4.
We locally installed PowerDNS and send all the queries to our local resolver (it's not fair to use public recursive resolver like 1.1.1.1 as it puts a lot of pressure).
Here is the result of the comparison: We perform the tests on two datasets: 1) Top 1 million domains names of Cloudflare and 2) 10 million domain names randomly selected from all TLDs.

|#|Tool|DB size|Time|Success Ratio|Resource Record|
|---|---|-------|-----|-------------|-------------|
|1| ZDNS|1M|4m59s|99.45%|A Record|
|2|bulkDNS|1M|4m32s|99.99%|A Record|
|3|massDNS|1M|6m33s|99.51%|A Record|
|4|bulkDNS+Lua|1M|5m32s|99.47%|A Record|
|-|-----------|--|----|-----|---------|
|5|ZDNS|1M|5m15s|98.57%|TXT Record|
|6|bulkDNS|1M|7m12s|99.99%|TXT Record|
|7|massDNS|1M|6m57s|99.26%|TXT Record|
|8|bulkDNS+Lua|1M|5m59s|99.03%|TXT Record|

And here is the result for 10M randomly selected domain names from All TLDs:

|#|Tool|DB size|Time|Success Ratio|Resource Record|
|---|---|-------|-----|-------------|-------------|
|1|ZDNS|10M|55m3s|99.75%|A Record|
|2|bulkDNS|10M|49m43s|99.99|A Record|
|3|massDNS|10M|68m44s|95.98%|A Record|
|4|bulkDNS+Lua|10M|60m45s|99.70%|A Record|

1. All the times are wall clock time.
2. The success rate is calculated based on the answers we get from the server.
3. Due to the different architecture of the tools, we tried to launch each tool based on its options and switches in a way that it sends 1,000 concurrent requests.
4. We set the timeout of all experiments to 3 seconds (default option for each tool is different for example, ZDNS has the default option of 15 seconds).
5. We used the default output option of each tool (some tools like massDNS supports several output options).
6. Cloudflare domain ranking list can be downloaded from [here](https://radar.cloudflare.com/domains)

### Supported Resource Records

Currently, bulkDNS supports the following 17 RRs:

**A**, **AAAA**, **NS**, **RRSIG**, **SOA**, **MX**, **SRV**, **PTR**, **HINFO**, **TXT**, **CNAME**, **URI**, **NID**, **L32**, **L64**, **LP**, **CAA**

It also supports adding **EDNS0** (**DNSSEC-OK** and **NSID**) to queries.

All the RRs and EDNS0 are implemented based on the following RFCs (Some implemented partially):

- **RFC 1034**: DOMAIN NAMES - CONCEPTS AND FACILITIES
- **RFC 1035**: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- **RFC 6742**: DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)
- **RFC 3596**: DNS Extensions to Support IP Version 6
- **RFC 6891**: Extension Mechanisms for DNS (EDNS(0))
- **RFC 2782**: A DNS RR for specifying the location of services (DNS SRV)
- **RFC 7553**: The Uniform Resource Identifier (URI) DNS Resource Record
- **RFC 7873**: Domain Name System (DNS) Cookies
- **RFC 8914**: Extended DNS Errors
- **RFC 5001**: DNS Name Server Identifier (NSID) Option
- **RFC 6844**: DNS Certification Authority Authorization (CAA) Resource Record

### List of Switches
```
[Help]

Summary:
Bulk DNS scanner based on sdns low-level DNS library.

./bulkdns [OPTIONS] <INPUT|FILE>	

	-t <param>, --type=<param>	Resource Record type (Default is 'A')
	-c <param>, --class=<param>	RR Class (IN, CH). Default is 'IN'
	-r <param>, --resolver=<param>	Resolver IP address to send the query to (default 1.1.1.1)
	-p <param>, --port=<param>	Resolver port number to send the query to (default 53)
	-e <param>, --error=<param>	where to write the error (default is terminal with stderr)
	-o <param>, --output=<param>	Output file name (default is the terminal with stdout)
	--lua-script=<param>		Lua script to be used either for scan or server mode
	--bind-ip=<param>		IP address to bind (default 127.0.0.1 for scan mode, 0.0.0.0 for server-mode)
	--timeout=<param>		Timeout of the socket (default is 5 seconds)
	--concurrency=<param>		How many concurrent requests should we send (default is 1000)
	--udp-only			Only query using UDP connection (Default will follow TCP)
	--set-do			Set DNSSEC OK (DO) bit in queries (default is no DO)
	--set-nsid			The packet has NSID in edns0
	--noedns			Do not support EDNS0 in queries (Default supports EDNS0)
	--server-mode			Run bulkDNS in server mode
	-h, --help			Print this help message

bulkDNS currently supports the following RRs:
	A, AAAA, NS, RRSIG, SOA, MX, SRV, URI, PTR,
	HINFO, TXT, CNAME, NID, L32, L64, LP, CAA
Supported DNS classes: IN, CH
```

### Example Output

Providing the following input

```bash
echo -n 'google.com' | ./bulkdns -t A -c IN -r 1.1.1.1
```
You will get the following JSON output:

```text
{
    "header": {
        "ID": 17493,
        "opcode": 0,
        "rcode": "NoError",
        "qdcount": 1,
        "ancount": 1,
        "arcount": 1,
        "nscount": 0, 
        "flags": {
            "qr": 1,
            "aa": 0,
            "tc": 0,
            "rd": 1,
            "ra": 1,
            "z": 0,
            "AD": 0,
            "CD": 0
        }
    },
    "question": {
        "qname": "google.com.",
        "qclass": "IN",
        "qtype": "A"
    },
    "answer": [
        {
            "name": "google.com.",
            "class": "IN",
            "type": "A",
            "ttl": 135,
            "rdlength": 4,
            "rdata": {
                "address": "142.251.37.206"
            }
        }
    ],
    "authority": [],
    "additional": []
}
```
We try to keep the output as close as possible to DNS RFC standards. 

### Notes

#### A note on threads and concurrency

* bulkDNS is capable of scanning 1,000,000 (1M) domain names in around 5 minutes with less than 1% of errors using default number of threads (1000). That means you can
scan the whole domain name system in less than one day.
This makes it probably the most practical (and maybe fastest) DNS scanner. It does not have any requirements in terms of CPU or RAM. As all other network scanners,
the bottleneck is always the network bandwidth, firewalls and the remote recursive resolver. We recommend using Cloudflare quad one (1.1.1.1) as the resolver since 
it has no limit in terms of the number of queries. However, you can also run your own recursive resolver to do the job. If you decrease the concurrency, you can
also use google quad-eight (8.8.8.8) which has 1,500 queries/second limit.

* Using `--concurrency` option, you can increase or decrease the number of concurrent requests based on your network and your experience. It's important to note that if you set `--concurrency=1000`, it means you ask for openning 1,000
sockets (which means binding to 1,000 ports) at the same time.

* If you are running the scanner on Linux, the maximum number of open files is 1024 by default. So if you plan to set
the `--concurrency` to a value greater than 1000, then you need to increse the limit of open files using `ulimit -n` commands.



#### Names and output convention

* You can check the IANA standard DNS rcodes [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
* We try to keep the output names as close to what you can find in RFCs. However, sometimes RFC names are __Bizarre__ and that's why some names are wierd!

#### Hex represantaion of the output

* For `HINFO` RR, the value of `os` and `cpu` will be encoded as hex. The reason is that these are not necessarily null-terminated strings.

* FOR `URI` RR, the value of the `target` will be encoded as hex since the value is not guaranteed to be a null-terminated, human-readable string.

* For `RRSIG` RR, the value of the `signature` will be encoded as hex since the value is a key and not a null-terminated string.

example:
```bash
echo -n 'hinfo-example.lookup.dog.' | ./bulkdns -r 1.1.1.1 -t HINFO
````

answer
```text
{
    "header": {
        "ID": 31890, "opcode": 0, "rcode": "NoError", "qdcount": 1, "ancount": 1, "arcount": 1, "nscount": 0, 
        "flags": {"qr": 1, "aa": 0, "tc": 0, "rd": 1, "ra": 1, "z": 0, "AD": 0, "CD": 0}
    }, 
    "question": {
        "qname": "hinfo-example.lookup.dog.", "qclass": "IN", "qtype": "HINFO"
    }, 
    "answer": [
        {
            "name": "hinfo-example.lookup.dog.", 
            "class": "IN", "type": "HINFO", "ttl": 3600, "rdlength": 29, 
            "rdata": {
                "cpu": "736f6d652d6b696e64612d637075", 
                "os": "736f6d652d6b696e64612d6f73"
            }
        }
    ], 
    "authority": [], "additional": []
}
```

In the above example the `cpu` is the hex represantation of `some-kinda-cpu` and os is the hex represantation of `some-kinda-os`.

### Using Lua for customized scan scenario

Using bulkDNS, you can write your own modules to perform any type of scan. The [modules](./modules) directory contains
a tutorial on how to create a custom scan module along with several examples. To use this feature, you must compile bulkDNS
with Lua library.

### Running bulkDNS in server mode

bulkDNS is not just a scanner. You can also run it in server mode by passing `--server-mode` switch. 
If you want to run bulkDNS in server mode, you must compile it with Lua library.
In the server mode, bulkDNS acts like a DNS server. A complete tutorial provided in [modules](./modules) directory
along with examples. For example, [URLAbuse DNSBL](https://dbl.urlabuse.com) is running on top of bulkDNS server mode.


### FAQ
1. Why another scanner?
   - Because It's fun!
1. Why not using CMake in the project?
   - I don't know CMake
2. Is there any similar project like this?
   - The only comparable project to this one (that I'm aware of) is zmap/zdns. 
3. Can I pass a domain name (e.g., `ns1.google.com`) as the resolver?
   - No. The resolver must be an IPv4 address. We pass this value to `inet_addr()` function which accepts an IPv4.
4. How fast it can scan domain names?
   - It highly depends on your network and the (remote) resolver you use.
5. Why scanning one domain name takes much time?
   - bulkDNS designed to be used for large-scale measurement. At the time of initialization, it launches dozens of threads in the memory. Therefore,
   it's not suitable for scanning one domain name. You can use dig for that!
