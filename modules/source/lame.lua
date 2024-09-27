-- This module (partially) implemented lame delegation
-- explained in the paper "Unresolved Issues: Prevalence, Persistence, and Perils of Lame Delegations"
-- published in IMC2020 https://cseweb.ucsd.edu/~gakiwate/papers/unresolved_issues-imc20.pdf
-- 
-- We don't perform full scan to check inconsistency or servfail from a nameserver of a domain name.
-- We are just interested in nameservers that don't exists (or probably not in the zone file for any reason like clientHold).
-- These cases are interesting and more dangerous since anyone can register them and take control of all the domains names
-- with this name-server.
-- 
-- This code implemented as a module for bulkDNS.
-- speed test: ~100K domains scanned in 4m26s wall clock
-- License: MIT
-- Author: S.MAROOFI

local sdns = require("libsdns")         -- you have it if you are using bulkDNS
local inspect = require("inspect")      -- luarocks --local install inspect
local json = require("json")            -- I have it in this directory
local psl = require("psl")              -- luarocks --local install psl

-- keeps the name-servers IP address. Serves as a cache system
-- since we keep the Lua state in C code
local nameservers = {}

-- to extract the registrable domain name from nameserver
-- ns1.google.com -> google.com
local p = psl.builtin()
assert(p)

-- split function to get the suffix
function string:split(sep)
   local sep, fields = sep or ":", {}
   local pattern = string.format("([^%s]+)", sep)
   self:gsub(pattern, function(c) fields[#fields+1] = c end)
   return fields
end


function main(line)
    -- line is a domain name  or nil (only as the last call of the function)
    -- here is the algorithm:
    -- 1. extract the name server of the domain name (using upper server in nameservers var)
    -- 2. query the nameserver (soa) to see if it returns NX or not
    -- 3. if the return value is NX then it's a lame nameserver
    -- 4. print it out along with the name servers

    -- we don't process nil data
    if line == nil then return nil end

    -- extract TLD to find the upper server
    local tld = line:split(".")
    if #tld < 2 then return nil end
    tld = tld[#tld]

    if nameservers[tld] == nil then
        -- find the nameserver and add it to global variable
        local query = sdns.create_query(tld, "NS", "IN")
        query = sdns.to_network(query)
        to_send = {dstport=53, dstip="1.1.1.1", timeout=2, to_send=query}
        local result = sdns.send_udp(to_send)
        if result == nil then return nil end
        result = sdns.from_network(result)
        if result == nil then return nil end
        local header = sdns.get_header(result)
        if header == nil then return nil end
        if header.ancount == 0 then return nil end
        local ns = sdns.get_answer(result, 1)
        if ns == nil then return nil end
        if ns.class == "IN" and ns["type"] == "NS" then
            query = sdns.create_query(ns.rdata.nsname, "A", "IN")
            query = sdns.to_network(query)
            if query == nil then return nil end
            to_send.to_send = query
            result = sdns.send_udp(to_send)
            if result == nil then return nil end
            result = sdns.from_network(result)
            if result == nil then return nil end
            header = sdns.get_header(result)
            if header == nil then return nil end
            if header.ancount == 0 then  return nil end
            local arec = sdns.get_answer(result, 1)
            if arec == nil then return nil end
            if arec.class == "IN" and arec["type"] == "A" then
                if arec.rdata ~= nil and arec.rdata.ip ~= nil then
                    nameservers[tld] = arec.rdata.ip
                else
                    return nil
                end
            else
                return nil
            end
        else
            return nil
        end
    end
    -- we have the upper server IP address. now query NS of the input domain
    local query = sdns.create_query(line, "NS", "IN")
    query = sdns.to_network(query)
    if query == nil then return nil end
    local to_send = {dstport=53, dstip=nameservers[tld], timeout=2, to_send=query}
    local result = sdns.send_udp(to_send)
    if result == nil then return nil end
    result = sdns.from_network(result)
    if result == nil then return nil end
    local header = sdns.get_header(result)
    if header.rcode ~= 0 then return nil end
    if header.nscount < 1 then return nil end
    local firstns = sdns.get_authority(result, 1)
    firstns = ((firstns or {}).rdata or {}).nsname or nil
    if firstns == nil then return nil end
    firstns_rd = p:registrable_domain(firstns)
    if firstns_rd == nil then return nil end
    query = sdns.create_query(firstns_rd, "SOA", "IN")
    query = sdns.to_network(query)
    if query == nil then return nil end
    to_send.to_send = query
    to_send.dstip = "1.1.1.1"
    result = sdns.send_udp(to_send)
    if result == nil then return nil end
    result = sdns.from_network(result)
    if result == nil then return nil end
    header = sdns.get_header(result)
    if header.rcode ~= nil and header.rcode == 3 then
        return json.encode({ns=firstns, domain=line})
    end
    return nil
end
