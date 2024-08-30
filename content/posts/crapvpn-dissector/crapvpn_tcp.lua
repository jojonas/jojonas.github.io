do
    local crapvpn_proto = Proto("CrapVPN_TCP", "CrapVPN Protocol (TCP)")

    local ip_dissector = Dissector.get("ip")

    local fields = {
        magic_bytes = ProtoField.string("crapvpn.magic", "Magic Bytes"),
        ciphertext_length = ProtoField.uint16("crapvpn.ciphertext_length", "Ciphertext Length", base.DEC),
        ciphertext = ProtoField.bytes("crapvpn.ciphertext", "Ciphertext")
    }
    crapvpn_proto.fields = fields

    crapvpn_proto.prefs.key = Pref.string("Key", "", "Key used for decryption (provided as hex string)")

    local function decrypt(ciphertext)
        local hex_key = crapvpn_proto.prefs.key
        if not hex_key or hex_key == "" then
            return
        end

        local key = ByteArray.new(hex_key)

        local plaintext = ByteArray.new()
        plaintext:set_size(ciphertext:len())

        for idx = 0, ciphertext:len() - 1 do
            local k = key:get_index(idx % key:len())
            local c = ciphertext:get_index(idx)
            local p = bit.bxor(c, k)
            plaintext:set_index(idx, p)
        end

        return plaintext
    end

    function crapvpn_proto.dissector(buffer, pinfo, tree)
        if buffer:captured_len() ~= buffer:reported_len() then
            return 0
        end

        local offset = 0

        pinfo.cols.protocol = crapvpn_proto.name

        repeat
            local header_length = 6
            if buffer:len() < header_length then
                pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                pinfo.desegment_offset = offset
                pinfo.cols.protocol = "FUCKED"
                return
            end

            local magic_bytes_buffer = buffer(0, 4)
            if magic_bytes_buffer:string() ~= "crap" then
                -- packet is not for us
                return 0
            end

            local subtree = tree:add(crapvpn_proto, buffer(), crapvpn_proto.description)
            subtree:add(fields.magic_bytes, magic_bytes_buffer)

            local ciphertext_length_buffer = buffer(4, 2)
            subtree:add(fields.ciphertext_length, ciphertext_length_buffer)

            local ciphertext_length = ciphertext_length_buffer:uint()

            local total_length = header_length + ciphertext_length
            if total_length > buffer:len() then
                local missing_length = total_length - buffer:len()
                pinfo.desegment_len = missing_length
                pinfo.desegment_offset = offset
                return
            end

            local ciphertext_buffer = buffer(header_length, ciphertext_length)
            subtree:add(fields.ciphertext, ciphertext_buffer)

            local ciphertext_bytes = ciphertext_buffer:bytes()
            local plaintext_bytes = decrypt(ciphertext_bytes)
            if plaintext_bytes then
                local plaintext_tvb = plaintext_bytes:tvb("Plaintext")
                pcall(Dissector.call, ip_dissector, plaintext_tvb, pinfo, tree)
            end

            offset = offset + total_length
            buffer = buffer(total_length):tvb()
        until buffer:len() == 0
    end

    local tcp_port = DissectorTable.get("tcp.port")
    tcp_port:add(1337, crapvpn_proto)
end
