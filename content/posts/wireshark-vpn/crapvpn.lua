do
    local crapvpn_proto = Proto("CrapVPN_UDP", "CrapVPN Protocol (UDP)")

    local ethertype_dissector_table = DissectorTable.get("ethertype")

    local fields = {
        magic_bytes = ProtoField.string("crapvpn.magic", "Magic Bytes"),
        ciphertext_length = ProtoField.uint16("crapvpn.ciphertext_length", "Ciphertext Length", base.DEC),
        ciphertext = ProtoField.bytes("crapvpn.ciphertext", "Ciphertext"),
        ethertype = ProtoField.uint16("crapvpn.ethertype", "Ether Type", base.HEX)
    }
    crapvpn_proto.fields = fields

    crapvpn_proto.prefs.key = Pref.string("Key", "", "Key used for decryption (provided as hex string)")

    local function xor_decrypt(ciphertext)
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
        local length = buffer:len()
        if length == 0 then return end

        pinfo.cols.protocol = crapvpn_proto.name
        local subtree = tree:add(crapvpn_proto, buffer(), crapvpn_proto.description)

        local magic_bytes_buffer = buffer(0, 4)
        subtree:add(fields.magic_bytes, magic_bytes_buffer)

        if magic_bytes_buffer:string() ~= "crap" then
            -- packet is not for us
            return 0
        end

        local ciphertext_length_buffer = buffer(4, 2)
        subtree:add(fields.ciphertext_length, ciphertext_length_buffer)


        local ethertype_buffer = buffer(6, 2)
        subtree:add(fields.ethertype, ethertype_buffer)

        local ciphertext_length = ciphertext_length_buffer:uint()
        local ciphertext_buffer = buffer(8, ciphertext_length)
        subtree:add(fields.ciphertext, ciphertext_buffer)

        local ciphertext_bytes = ciphertext_buffer:bytes()
        local plaintext_bytes = xor_decrypt(ciphertext_bytes)
        if plaintext_bytes then
            local plaintext_tvb = plaintext_bytes:tvb("Plaintext")
            local ethertype = ethertype_buffer:uint()
            ethertype_dissector_table:try(ethertype, plaintext_tvb, pinfo, tree)
        end
    end

    local udp_port = DissectorTable.get("udp.port")
    udp_port:add(1337, crapvpn_proto)
end
