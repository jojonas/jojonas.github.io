---
title: "Working with TCP Streams in Wireshark Dissectors"
date: 2024-10-03T09:33:34+02:00
draft: true
tags: ["Wireshark", "Reverse Engineering", "Networking"]
series: ["Wireshark Dissector Guides"]
---


TCP operates on _streams_, not packets. Stream reassembly is a rather complex process, but it's already implemented in Wireshark and can be used by dissectors. The API is described in [this article from Wireshark's documentation](https://wiki.wireshark.org/Lua/Dissectors#tcp-reassembly), but I found the description rather bulky. 

From my understanding, the most important things to consider when writing dissectors operating on TCP are (in that order):
 1. The dissector may be called with truncated frames - the easiest solution is to ignore (i.e. `return 0`) buffers that are truncated:

    ```lua
    if buffer:captured_len() ~= buffer:reported_len() then
        return 0
    end
    ```

 1. The dissector may be called for the "middle" packet of your message, so you should figure out _as early as possible_ whether the `buffer` points to the _start_ of a valid packet or not, e.g. by checking for magic bytes. Again, `return 0` to ignore the packet:

    ```lua
    local magic_bytes_buffer = buffer(0, 4)
    if magic_bytes_buffer:string() ~= "crap" then
        -- packet is not for us
        return 0
    end
    ```

 1. The dissector may be called before the entire message as been received, so you should figure out the packet length and check if bytes are missing. If this is the case, set `desegment_len` and `desegment_offset` accordingly, and return, but **do not return `0`**:
    
    ```lua
    local header_length = 6 -- 4 bytes magic + 2 bytes length field
    if buffer:len() < header_length then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        pinfo.desegment_offset = 0
        return -- do NOT return 0!
    end
    
    local payload_length = ... -- read the header and the included payload length

    local total_length = header_length + payload_length
    if total_length > buffer:len() then
        pinfo.desegment_len = total_length - buffer:len()
        pinfo.desegment_offset = 0
        return -- do NOT return 0!
    end
    ```

    As a bonus, you can use the `total_length` to correctly update your subtree:

    ```lua
    subtree:set_len(total_length)
    ```

 1. The dissector may be called once for multiple subsequent messages, so you need to split them and parse them separately. This is the most complicated one, and I don't have an ideal solution yet, but wrapping the dissector in a `repeat ... until` loop works fairly well:

    ```lua {hl_lines=["1-2",9,"13-16"]}
    local offset = 0
    repeat
        -- ... do all the dissections on buffer() here, including calculating the total_length

        -- similar to before, but jump to the offset instead of the beginning of the packet
        local total_length = header_length + payload_length
        if total_length > buffer:len() then
            pinfo.desegment_len = total_length - buffer:len()
            pinfo.desegment_offset = offset -- <== this is different
            return
        end

        offset = offset + total_length
        buffer = buffer(total_length):tvb()
    until buffer:len() == 0
    ```


TODO: look into `dissect_tcp_pdus`