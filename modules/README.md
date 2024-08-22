## Modules for bulkDNS


bulkDNS modules are written in Lua programming language. This tutorial shows how to write a module for a customized scan scenarios using Lua and bulkDNS. Before writing modules, you need to make sure to compile bulkDNS with Lua (using `make with-lua', by following the instruction in the main README file.)

### How to write a module for customized scan scenario

BulkDNS accepts a Lua script file using the switch `--lua-script`. After launching the scanner, each thread (pthread) creates a Lua state in the memory, run the file one time and then for each entry, it calls the `main` function in the Lua file. Therefore, your Lua script must have a `main` function which accepts only one parameter: *one line of the input file passed to bulkDNS*.

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

        return "whatever you return will be stored in output"
    end
```

If you return `nil` from the `main` function, then nothing will be logged in the output. This is very useful and we'll see an example later.

It's also very important to note that whatever global variable you define in your Lua file will be available until the end of the scan. This is on purpose! In this way, you can keep the states for different entries and have a dynamic scan. For examle, one use-case of this feature is to implement a global LRU DNS cache in your Lua file!

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

I am using the json library from [here](https://github.com/rxi/json.lua). I sotred it in the module directory.


You can find more modules in this directory and all are documented.


### Running bulkDNS in Server mode

**TODO**: write this part.