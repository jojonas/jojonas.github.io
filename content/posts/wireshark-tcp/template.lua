do
    local my_proto = Proto("MyProto", "My Proto (TCP)")

    local fields = {}
    my_proto.fields = fields

    function my_proto.dissector(buffer, pinfo, tree)
        if buffer:captured_len() == 0 then return 0 end
        if buffer:captured_len() ~= buffer:reported_len() then return 0 end

        pinfo.cols.protocol = my_proto.name

        local offset = 0

        while buffer:reported_len_remaining(offset) > 0 do
            local packet_offset = offset

            -- Example protocol:
            --  0                   1                   2                   3  
            --  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            -- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            -- |                             Magic                             |
            -- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            -- |                         Payload Length                        |
            -- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            -- |                                                               |
            -- +                            Payload                            +
            -- |                                                               |
            -- +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            local header_length = 8 -- adapt this for your header length
            if buffer:len() < header_length then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                pinfo.desegment_offset = packet_offset
                return
            end

            local magic_bytes = buffer(offset, 4):string()
            offset = offset + 4

            if magic_bytes ~= "crap" then
                -- packet is not for us
                return 0
            end

            local payload_length = buffer(offset, 4):uint()
            offset = offset + 4

            if buffer:reported_len_remaining(offset) < payload_length then
                pinfo.desegment_len = payload_length - buffer:reported_len_remaining(offset)
                pinfo.desegment_offset = packet_offset
                return
            end

            local payload_tvb = buffer(offset, payload_length)
            offset = offset + payload_length

            -- handle payload
        end
    end

    local tcp_port = DissectorTable.get("tcp.port")
    tcp_port:add(1337, my_proto)
end
