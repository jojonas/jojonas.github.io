#include <stdio.h>

#include <lua.h>
#include <lauxlib.h>

static int lexample_greet(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    if (name == NULL)
        luaL_error(L, "name cannot be empty");

    printf("Hello %s!\n", name);
    return 0;
}

static const struct luaL_Reg lexample_functions[] = {
    {"greet", lexample_greet},
    {NULL, NULL},
};

int luaopen_lexample(lua_State *L) {
    luaL_newlib(L, lexample_functions);
    return 1;
}
