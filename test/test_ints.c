#include "dbus-util.h"
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>

#define CHECKERR(x) do{int ret = (x);if(ret != 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)
#define CHECKERRN(x) do{int ret = (x);if(ret == 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)

bool running;
int ready_fd[2];

void reply_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    int32_t int32;
    uint32_t uint32;
    dbus_util_message_context_get_int32(ctx, &int32);
    dbus_util_message_context_get_uint32(ctx, &uint32);

    CHECKERRN(int32 == 3333 && uint32 == 99999999);
    int read_sig = 4;
    write(ready_fd[1], &read_sig, sizeof(read_sig));
    running = false;
}

int child_main() {
    int ready_sig = 0;
    while (ready_sig != 2) {
        read(ready_fd[0], &ready_sig, sizeof(ready_sig));
    }

    dbus_bus *bus;
    dbus_util_create_bus(&bus);

    dbus_method_call *call = dbus_util_new_method_call("me.quartzy.dbusutil.testints", "/",
                                                       "me.quartzy.dbusutil.testints", "Test");

    dbus_message_context *ctx = dbus_util_make_write_context(call);

    dbus_util_message_context_add_byte(ctx, 42);
    dbus_util_message_context_add_bool(ctx, false);
    dbus_util_message_context_add_int16(ctx, 2321);
    dbus_util_message_context_add_uint16(ctx, 39102);
    dbus_util_message_context_add_int32(ctx, 38812);
    dbus_util_message_context_add_uint32(ctx, 38312324);
    dbus_util_message_context_add_int64(ctx, 38388381);
    dbus_util_message_context_add_uint64(ctx, 83838383883);
    dbus_util_message_context_add_double(ctx, 23.223);

    dbus_util_message_context_free(ctx);

    CHECKERR(dbus_util_send_method(bus, call, reply_cb, NULL));
    dbus_util_free_method_call(call);

    while (running) {
        dbus_util_poll_messages(bus);
        usleep(10000);
    }
    dbus_util_free_bus(bus);

    return 0;
}

void method_cb(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
               void *param) {
    int8_t byte;
    bool boolean;
    int16_t int16;
    uint16_t uint16;
    int32_t int32;
    uint32_t uint32;
    int64_t int64;
    uint64_t uint64;
    double dbl;

    dbus_message_context *ctx = dbus_util_make_read_context(call);
    CHECKERRN(ctx != NULL);

    CHECKERR(dbus_util_message_context_get_byte(ctx, &byte));
    CHECKERR(dbus_util_message_context_get_bool(ctx, &boolean));
    CHECKERR(dbus_util_message_context_get_int16(ctx, &int16));
    CHECKERR(dbus_util_message_context_get_uint16(ctx, &uint16));
    CHECKERR(dbus_util_message_context_get_int32(ctx, &int32));
    CHECKERR(dbus_util_message_context_get_uint32(ctx, &uint32));
    CHECKERR(dbus_util_message_context_get_int64(ctx, &int64));
    CHECKERR(dbus_util_message_context_get_uint64(ctx, &uint64));
    CHECKERR(dbus_util_message_context_get_double(ctx, &dbl));

    dbus_util_message_context_free(ctx);

    CHECKERRN(byte == 42 && boolean == false && int16 == 2321 && uint16 == 39102 && int32 == 38812 &&
              uint32 == 38312324 && int64 == 38388381 && uint64 == 83838383883 && fabs(dbl - 23.223) < 0.001);

    ctx = dbus_util_make_reply_context(call);

    dbus_util_message_context_add_int32(ctx, 3333);
    dbus_util_message_context_add_uint32(ctx, 99999999);

    dbus_util_message_context_free(ctx);
    running = false;
}

int main() {
    running = true;
    if (pipe(ready_fd)) {
        perror("error when calling pipe");
        return 1;
    }
    if (!fork()) {
        return child_main();
    }

    dbus_bus *bus;
    CHECKERR(dbus_util_create_bus_with_name(&bus, "me.quartzy.dbusutil.testints"));
    FILE *fp = fopen("test_ints.xml", "r");
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    rewind(fp);
    char buf[len + 1];
    fread(buf, len, sizeof(*buf), fp);
    fclose(fp);
    buf[len] = 0;
    CHECKERR(dbus_util_set_introspectable_xml(bus, buf));
    CHECKERR(dbus_util_parse_introspection(bus));

    CHECKERR(dbus_util_set_method_cb(
            dbus_util_find_interface(dbus_util_find_object(bus, "/"), "me.quartzy.dbusutil.testints"), "Test",
            method_cb,
            NULL));

    int ready_sig = 2;
    write(ready_fd[1], &ready_sig, sizeof(ready_sig));

    while (running) {
        dbus_util_poll_messages(bus);
        usleep(10000);
    }
    dbus_util_free_bus(bus);

    while (ready_sig != 4) {
        read(ready_fd[0], &ready_sig, sizeof(ready_sig));
    }

    return 0;
}