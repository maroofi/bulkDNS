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
