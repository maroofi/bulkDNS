-- Send a packet to different IP addresses to check if they are resolvers or not.
-- you need json.lua in the same directory.
-- you also need to have sdns (https://github.com/maroofi/sdns) compiled with lua as a library in $LIB dir or current directory.
-- currently, the sample domain is `digikala.ir`, but you can change it to whatever you want or even make it randomly.
-- how to use: bulkdns --lua-script=find_dns_resolver.lua <input-IP-list-file>
-- <input-IP-list-file>: is a file with one IP address per line.
-- The scanner is fast, capable of scanning millions of IPs in hours.
-- it scans for UDP(53), you can simply change it to TCP(53).
-- read the LUA API doc here: https://github.com/maroofi/sdns/blob/main/lua/DOCLUASDNS.md
-- The script will print out the working IP addresses.

local json = require "json"
local sdns = require "libsdns"

local find = string.find
local json_encode = json.encode
local insert = table.insert

assert(sdns ~= nil)

function main(line)
    if line == nil then return nil end
    local query, err, result, response
    query, err = sdns.create_query("digikala.ir", "A", "IN")
    assert(query)
    assert(err == nil)
    query, err = sdns.to_network(query)
    assert(query ~= nil)
    assert(err == nil)

    query = {dstport=53, dstip=line, timeout=2, to_send=query}
    result, err = sdns.send_udp(query)
    if result == nil then return nil end
    response, err = sdns.from_network(result)
    if response == nil then return nil end
    return line
end
