#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <lua.h>
#include <lauxlib.h>

// this is the "crypto" function that is being wrapped
void xor(const uint8_t *key, const size_t key_length, const uint8_t *in, const size_t in_length, uint8_t **out, size_t *out_length) {
    *out_length = in_length;
    uint8_t *buffer = (uint8_t *)malloc(*out_length);

    for (size_t i = 0; i < in_length; i++)
    {
        buffer[i] = in[i] ^ key[i % key_length];
    }

    *out = buffer;
};

// this is the userdata struct that holds the state (i.e. the key)
typedef struct {
    uint8_t *key;
    size_t key_length;
} cipher_userdata_t;

// lxor.new("key"), constructor for cipher
static int cipher_new(lua_State *L)
{
    cipher_userdata_t *u;
    const uint8_t *key;
    size_t key_length;

    key = (uint8_t *)luaL_checklstring(L, 1, &key_length);
    if (key == NULL)
        luaL_error(L, "key cannot be empty");

    u = (cipher_userdata_t *)lua_newuserdata(L, sizeof(*u));
    u->key_length = 0;
    u->key = NULL;

    luaL_getmetatable(L, "LXorCipher");
    lua_setmetatable(L, -2);

    // important: make _copies_ of parameter values, as pointers will be invalid outside this function
    u->key_length = key_length;
    u->key = (uint8_t *)malloc(key_length);
    memcpy(u->key, key, key_length);

    return 1;
}

// cipher:encrypt("...")
static int cipher_encrypt(lua_State *L)
{
    cipher_userdata_t *u;
    const uint8_t *plaintext;
    uint8_t *ciphertext;
    size_t plaintext_length, ciphertext_length;

    u = (cipher_userdata_t *)luaL_checkudata(L, 1, "LXorCipher");
    plaintext = (uint8_t *)luaL_checklstring(L, 2, &plaintext_length);
    if (plaintext == NULL || plaintext_length == 0)
        luaL_error(L, "plaintext cannot be empty");

    xor(u->key, u->key_length, plaintext, plaintext_length, &ciphertext, &ciphertext_length);
    lua_pushlstring(L, ciphertext, ciphertext_length);

    return 1;
}

// cipher:decrypt("...")
static int cipher_decrypt(lua_State *L)
{
    // This is a special shortcut because xor is symmetric
    return cipher_encrypt(L);
}

// cipher "destructor"
static int cipher_destroy(lua_State *L)
{
    cipher_userdata_t *u;

    u = (cipher_userdata_t *)luaL_checkudata(L, 1, "LXorCipher");

    if (u->key != NULL)
    {
        memset(u->key, 0, u->key_length);
        free(u->key);
        u->key = NULL;
        u->key_length = 0;
    }

    return 0;
}

// userdata methods
static const struct luaL_Reg cipher_methods[] = {
    {"encrypt", cipher_encrypt},
    {"decrypt", cipher_decrypt},
    {"__gc", cipher_destroy},
    {NULL, NULL},
};

// library functions
static const struct luaL_Reg lxor_functions[] = {
    {"new", cipher_new},
    {NULL, NULL},
};

int luaopen_lxor(lua_State *L)
{
    // Create new metatable
    luaL_newmetatable(L, "LXorCipher");
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, cipher_methods, 0);

    // Register library
    luaL_newlib(L, lxor_functions);

    return 1;
}