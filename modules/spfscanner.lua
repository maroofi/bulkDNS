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
