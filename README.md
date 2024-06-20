
### bulkDNS: A fast DNS scanner for large-scale Internet measurement

Using **bulkDNS**, you can scan millions of domain names in a few minutes. The scanner has been designed to be fast with a very small footprint.

The detailed output of the scanner is in JSON which can be parsed both by command-line or any programming language.


### How to compile

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

### Supported Resource Records (RR):

Currently, bulkDNS supports the following 16 RRs:

**A**, **AAAA**, **NS**, **RRSIG**, **SOA**, **MX**, **SRV**, **PTR**, **HINFO**, **TXT**, **CNAME**, **URI**,
**NID**, **L32**, **L64**, **LP**

It also supports **EDNS0** for queries and responses.

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


### List of Switches
```
[Help]

Summary:
BulkDNS scanner based on sdns low-level DNS library.

./bulkdns [OPTIONS] <INPUT|FILE>
	            --udp-only 	Only query using UDP connection (Default will follow TCP)
	            --set-do 	Set DNSSEC OK (DO) bit in queries (default is no DO)
	            --noedns 	Do not support EDNS0 in queries (Default supports EDNS0)
	            --threads=<param>	How many threads should be used (it's pthreads, and default is 300)
	-t <param>, --type=<param>	Resource Record type (A, AAAA, NS, TXT, RRSIG, PTR, SOA, MX, SRV, CNAME, HINFO). Default is 'A'
	-c <param>, --class=<param>	RR Class (IN, CH). Default is 'IN'
	-r <param>, --resolver=<param>	Resolver IP address to send the query to (default 1.1.1.1)
	-p <param>, --port=<param>	Resolver port number to send the query to (default 53)
	-o <param>, --output=<param>	Output file name (default is the terminal with stdout)
	-e <param>, --error=<param>	where to write the error (default is terminal with stderr)
	-h ,         --help 	Print this help message

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

* bulkDNS is capable of scanning 1,000,000 (1M) domain names in around 5 minutes with less than 1% of errors using default number of threads (300). That means you can
scan the whole domain name system in less than one day.
This makes it probably the most practical (and maybe fastest) DNS scanner. It does not have any requirements in terms of CPU or RAM. As all other network scanners,
the bottleneck is always the network bandwidth, firewalls and the remote recursive resolver. We recommend using Cloudflare quad one (1.1.1.1) as the resolver since 
it has no limit in terms of the number of queries. However, you can also run your own recursive resolver to do the job. If you decrease the number of threads, you can
also use google quad eight (8.8.8.8) which has 1,500 queries/second limit.

* Using `--threads` option, you can increase or decrease the number of threads based on your network and your experience. However, at some point, more threads will probably 
make the scanner even slower (threads competing each other to acquire the lock). 

* If you are running the scanner on Linux, the maximum number of open files is 1024 by default which is three times more than the default number of threads in bulkDNS.
However, if you plan to run bulkDNS with more threads, you may want to increase the number of open files using the `ulimit -n` commands.

* The whole source code of the scanner is less than 600 lines and all in standard C. You can easily modify the source code to match your needs.

* You can check the IANA standard DNS rcodes [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)

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


