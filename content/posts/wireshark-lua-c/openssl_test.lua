require("luarocks.loader")

local openssl_cipher = require("openssl.cipher")
local openssl_rand = require("openssl.rand")

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

local key = ("00112233445566778899AABBCCDDEEFF"):fromhex()
local iv = openssl_rand.bytes(16)

print(iv:tohex())

local cipher = openssl_cipher.new("AES-128-CBC")
cipher:encrypt(key, iv, true)

local ciphertext = cipher:final("Hello World!")
print(ciphertext:tohex())
