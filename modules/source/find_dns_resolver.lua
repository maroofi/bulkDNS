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
