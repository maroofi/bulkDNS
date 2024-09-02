## Modules for bulkDNS


bulkDNS modules are written in Lua programming language. This tutorial shows how to write
a module for a customized scan scenarios using Lua and bulkDNS. Before writing modules, you
need to make sure to compile bulkDNS with Lua (using `make with-lua', by following the instruction in the main README file.)

* [How to write a module for customized scan scenarios](#How-to-write-a-module-for-customized-scan-scenarios)
    * [First example: find NXdomains](#First-example-find-NXdomains)
    * [Second example: SPF scanner](#Second-example-SPF-scanner)
* [Running bulkDNS in Server mode](#Running-bulkDNS-in-Server-mode)
    * [First example: Creating a DNS forwarder](#First-example-Creating-a-DNS-forwarder)
    * [Second example: Creating an authoritative name server](#Second-example-Creating-an-authoritative-name-server)

### How to write a module for customized scan scenarios

BulkDNS accepts a Lua script file using the switch `--lua-script`. After launching the scanner, each 
thread (pthread) creates a Lua state in the memory, run the file one time and then for each entry, it 
calls the `main` function in the Lua file. Therefore, your Lua script must have a `main` function which
accepts only one parameter: *one line of the input file passed to bulkDNS*.

The `main` function must return exactly one value: _whatever you want to log in the output file_.

Therefore, here is the structure of the Lua script you pass to bulkDNS.

```lua
    -- whatever import module you want
    --
    --
    -- whatever code or function you want to have

    -- if you define a global variable here, it will be
    -- available as long as bulkDNS is running
    -- for examle: 
    -- global_cache = {}


    function main(input_line)
        -- input_line: one of the entries of the input file
        -- you passed to bulkDNS

        -- body of the function
        -- body of the function
        -- body of the function

        return "whatever you return will be stored in the output file specifed with -o switch"
    end
```

If you return `nil` from the `main` function, then nothing will be logged in the output. This is very useful and we'll see an example later.

It's also very important to note that whatever global variable you define in your Lua file will be available 
until the end of the scan. This is on purpose! In this way, you can keep the states for different entries 
and have a dynamic scan. For examle, one use-case of this feature is to implement a global LRU DNS cache in your Lua file!

#### First example: find NXdomains

Here is the scan scenario: I have a list of domain names and I want to output only those with DNS response code of NXDomain.
We know that NXDomain is `rcode=3` in a DNS packet.
So here is the code in Lua:

```lua
-- save this code in a file nxscanner.lua

local sdns = require("libsdns")
assert(sdns)

function main(line)
    -- create a query packet
    local query = sdns.create_query(line, "A", "IN")
    -- make sure the query packet created successfully
    if query == nil then return nil end

    -- parameters for sending to cloudflare servers
    tbl_send = {dstport=53, timeout=3, dstip="1.1.1.1"}

    -- make a payload from our query packet
    to_send = sdns.to_network(query)

    -- make sure we created the payload successfully
    if to_send == nil then return nil end

    -- add it to our parameters
    tbl_send.to_send = to_send

    -- send it using sdns library
    from_udp = sdns.send_udp(tbl_send)

    -- make sure we have the answer payload
    if from_udp == nil then return nil end

    -- convert the payload to DNS packet
    answer = sdns.from_network(from_udp)

    -- make sure the conversion was successful
    if answer == nil then return nil end

    -- get the header of the DNS packet
    header = sdns.get_header(answer)

    -- make sure you got the header
    if header == nil then return nil end

    -- check if rcode==3 or not
    if header.rcode == 3 then
        -- send it to the output
        return line
    else
        return nil
    end
end
```

That's it! You just made a nice NX scanner!

Before running bulkDNS, make sure you don't have any syntax error. You can do it by running `lua nxscanner.lua` in your bash. You should get nothing as output.

Now create a list of domain names and store it in input_file.txt:
```text
microsoft.com
google.com
yahoo.com
filovirid.com
urlabuse.com
nonexistentdomainslakfjas.com
secondnotexistdomain234234.net
```

The last two domains must be in the output as they don't exist.

Run bulkDNS like this:
```bash
./bulkdns --lua-script=nxscanner.lua --concurrency=10 input_file.txt
```

it prints out the output in your terminal (you can specify a file to save the output using `-o` or `--output` switch).

You can download both `nxscanner.lua` and `input_file.txt` from this directory.

It's important to note that I used `sdns` lua library for doing DNS operation in Lua. However, you can use whatever Lua library that you prefer. For socket operation, you can also use other Lua libraries like [this one](https://lunarmodules.github.io/luasocket/). However, if you want to use `sdns` Lua library, make sure you follow [this tutorial](https://github.com/maroofi/sdns/blob/main/lua/README.md).


#### Second example: SPF scanner

In case you forgot, SPF stands for _**S**ender **P**olicy **F**ramework_.

We want to extract **only** the SPF records (not the whole TXT records) of a list of domain names. Here is the code to do the job:

```lua
-- save it in a file: spfscanner.lua
local json = require "json"
local sdns = require "libsdns"

local find = string.find
local json_encode = json.encode
local insert = table.insert

function main(line)
    local query = sdns.create_query(line, "TXT", "IN")
    if query == nil then return nil end
    tbl_send = {dstport=53, timeout=3, dstip="1.1.1.1"}
    to_send = sdns.to_network(query)
    if to_send == nil then return nil end
    tbl_send.to_send = to_send
    from_udp = sdns.send_udp(tbl_send)
    if from_udp == nil then return nil end
    answer = sdns.from_network(from_udp)
    if answer == nil then return nil end
    local header = sdns.get_header(answer)
    if header == nil then return nil end
    if header.tc == 1 then
        -- we need to do TCP
        from_tcp = sdns.send_tcp(tbl_send)
        if from_tcp == nil then return nil end
        answer = sdns.from_network(from_tcp)
        if answer == nil then return nil end
        header = sdns.get_header(answer)
    end
    local spf = {}
    question = sdns.get_question(answer) or {}
    local num = header.ancount or 0
    if num == 0 then return  nil end
    for i=1, num do
        a = sdns.get_answer(answer, i)
        a = ((a or {}).rdata or {}).txtdata or nil
        if a == nil then goto continue end
        if find(a, "^[vV]=[sS][pP][fF]1%s+") ~= nil then
            table.insert(spf, a)
        end
        ::continue::
    end
    return json_encode({name=line, data=spf});
end
```

And run it like:
```bash
./bulkdns --lua-script=spfscanner.lua --concurrency=10 input_file.txt
```

I am using the json library from [here](https://github.com/rxi/json.lua). I stored it in the module directory.


You can find more modules in this directory and all are documented.


### Running bulkDNS in Server mode

This awesome feature lets bulkDNS to work as a DNS server. Note that the purpose of
having this feature is not to use bulkDNS as a product-level DNS server. You must use
software like Bind9 or PowerDNS or Unbound for that.

However, if you are a researcher or a curious person want to have some experience 
with DNS and play a little bit by running your own customized server, then this is 
exactly what you need.

How can you use this feature:
```bash
./bulkdns --server-mode --lua-script=<your-lua-file> --bind-ip=YOUR-IPv4 -p PORT
```

`--server-mode` tells bulkDNS that instead of running the scanner, we want to run a 
DNS server.

`--lua-script` specifies the Lua script file which is responsible for handling
DNS requests.

`--bind-ip` tells bulkDNS to listen on this IP address for incoming connections.

`-p` or `--port` tells bulkDNS to listen to this port of the given IPv4.

bulkDNS listens to both TCP and UDP connections.

for example:
```bash
./bulkdns --server-mode --lua-script=server.lua -p 5300 --bind-ip=127.0.0.1
```

This command will listen and bind to 127.0.0.1:5300 on both TCP and UDP.

The structure of the Lua script must be like this:

```lua
-- import whatever module you want

-- you can have whatever global variable and function you want

function main(raw_data, client_info)
    --[[ 
        this function will be called for each requests that is received by bulkDNS
        the function has two parameters in each call.

        raw_data: this is the binary data the client sent to the socket
        client_info: This is a Lua table containing the client information
        client_info = {
            ip="client-IP-address", 
            port=client-port-number,
            proto="TCP or UDP"
        }

        This function MUST return exactly two values:
            1. string/nil: What you want to log in the output or file
            2. string/nil: What you want to send back to the client

        for example, if you return:
            nil, nil
        it means that you don't want to log anything and you don't want
        to return anything to the client.
    --]]

    -- body of the main function goes here.
    -- you can convert the raw_data to a DNS packet and decide to answer
    -- the user or not. You can also create the log string here.


    return log_string, response
end
```

Each time the client ask for something, the bulkDNS thread will call the 
`main` function in Lua script and return the response back to the client and
log the data in the output.

#### First example: Creating a DNS forwarder

Let's write a simple DNS forwarder as an example. Here is the explanation of Digicert
about DNS forwarder in case you don't know what it is:
[DNS forwarder](https://www.digicert.com/blog/understanding-dns-forwarding).

```lua
local json = require("json")
local sdns = require("libsdns")

-- Let's make sure we have all our libriries loaded
assert(json)
assert(sdns)

function main(raw_data, client_info)
    
  local dns = sdns.from_network(raw_data)
  if (dns == nil) then return nil, nil end

  local question = sdns.get_question(dns)
  if (question == nil) then return nil, nil end

  -- get the question to check the name of the query
  question.qname = question.qname or ""

  -- create the log anyway
  to_log = create_log(dns, client_info, question)
  
  -- do the forward operation
  -- ask question from 1.1.1.1 and forward the answer to the client
  return to_log, do_forward(raw_data, client_info)
end

function do_forward(raw_data, client_info)
    -- this function will do the forwarding part
    -- this function will do both UDP and 
    -- TCP (if it's necessary) to serve the answer
    local RR = {dstip="1.1.1.1", dstport=53, timeout=3}
    RR.to_send = raw_data
    local proto = client_info.proto
    if proto == "UDP" then return sdns.send_udp(RR) end
    if proto == "TCP" then return sdns.send_tcp(RR) end
end

function create_log(dns, client_info, question)
    -- this function will create the log line for us
    -- We send the log back to C code to store (or print) it.
    -- this is due to the fact that the code is multithreaded and we 
    -- don't want any race condition
    local err, msg;
    local ts = os.time(os.date("!*t"))
    local ip = client_info.ip or ""
    port = client_info.port or ""
    local data = {
        ip=ip, port=port, 
        proto=client_info.proto, 
        ["error"]="success", 
        ts=ts
    }
    data.question = {
        name=question.qname,
        ["type"]=question.qtype,
        ["class"]=question.qclass
    }
    return json.encode(data)
end
```

That's it! Now run bulkDNS with the following command:
```bash
./bulkdns --server-mode --bind-ip=127.0.0.1 -p 5300 --lua-script=forwarder.lua
```

Now use dig to query for the `A` record of `google.com`
```bash
dig @127.0.0.1 -p 5300 A google.com
```

If you want to run it on your server, you can use `0.0.0.0` for `--bind-ip` and
run it on port 5300 but use `iptables` to reroute the packets from port 53 to 5300.

Something like this would work:

```bash
# change PUBLICIP to your server's public IPv4 
iptables -t nat -I PREROUTING -p udp --dport 53 -j DNAT --to PUBLICIP:5300
```

#### Second example: Creating an authoritative name server

Now let's see another poor example of an authorative server: Let's say we want to manage
our own DNS server for a domain name. Our domain name is `example.com` and we want
to serve our IP address for this domain which is `1.2.3.4`. we have the same IP address
for our name-server which is `ns1.example.com`.

```lua
local sdns = require("libsdns")
local json = require("json")

assert(sdns)
assert(json)


function main(raw_data, client_info)
    local dns = sdns.from_network(raw_data)
    local lower = string.lower
    if raw_data == nil then return nil, nil end
    local question = sdns.get_question(dns)
    if question.qclass ~= "IN" then return nil, nil end
    if question.qtype ~= "A" and question.qtype ~= "NS" then return nil, nil end
    if question.qname == nil then return nil, nil end
    if question == nil then return nil, nil end
    local response = sdns.create_response_from_query(dns)
    print(question.qname)
    if lower(question.qname) == 'example.com.' then
        if question.qtype == 'A' then
            sdns.add_rr_A(response, {
                         ttl=300, rdata={ip="1.2.3.4"}, 
                         name=question.qname, section="answer"}
            )
            local response_raw = sdns.to_network(response)
            return create_log(nil, client_info, question), response_raw
        else
            sdns.add_rr_NS(response, {
                         ttl=300, rdata={nsname="ns1.example.com"}, 
                         name=question.qname, section="answer"}
            )
            sdns.add_rr_A(response, {
                     ttl=300, rdata={ip="1.2.3.4"}, 
                     name=question.qname, section="additional"}
            )
            local response_raw = sdns.to_network(response)
            return create_log(nil, client_info, question), response_raw

        end
    end

    if lower(question.qname) == 'ns1.example.com.' and question.qtype== 'A' then
        sdns.add_rr_A(response, {
                     ttl=300, rdata={ip="1.2.3.4"}, 
                     name=question.qname, section="answer"}
        )
        local response_raw = sdns.to_network(response)
        return create_log(nil, client_info, question), response_raw
    end
    return nil, nil
end

function create_log(dns, client_info, question)
    -- this function will create the log line for us
    -- We send the log back to C code to store (or print) it.
    -- this is due to the fact that the code is multithreaded and we 
    -- don't want any race condition
    local err, msg;
    local ts = os.time(os.date("!*t"))
    local ip = client_info.ip or ""
    port = client_info.port or ""
    local data = {
        ip=ip, port=port, 
        proto=client_info.proto, 
        ["error"]="success", 
        ts=ts
    }
    data.question = {
        name=question.qname,
        ["type"]=question.qtype,
        ["class"]=question.qclass
    }
    return json.encode(data)
end
```

Now you can run bulkDNS and use dig for asking the following questions:
```bash
# asking for the A record of the nameserver
dig @127.0.0.1 -p 5300 A ns1.example.com

# asking for the NS record of the domain name
dig @127.0.0.1 -p 5300 NS example.com

# asking for the A record of the domain name
dig @127.0.0.1 -p 5300 A example.com

# this is an authoritative server. So any other question you ask, the packet will
# be dropped.

```




