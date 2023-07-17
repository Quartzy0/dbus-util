#include "dbus-util.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define CHECKERR(x) do{int ret = (x);if(ret != 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)
#define CHECKERRN(x) do{int ret = (x);if(ret == 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)

bool running;
int ready_fd[2];

void reply_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    const char *str, *obj;

    dbus_util_message_context_get_string(ctx, &str);
    dbus_util_message_context_get_object_path(ctx, &obj);

    CHECKERRN(!strcmp(str, "Another funky string\n!") && !strcmp(obj, "/not/very/long/object"));
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

    dbus_method_call *call = dbus_util_new_method_call("me.quartzy.dbusutil.teststr", "/",
                                                       "me.quartzy.dbusutil.teststr", "Test");

    dbus_message_context *ctx = dbus_util_make_write_context(call);

    const char *str_out = "funny string test", *obj_out = "/also/just/funny/string/but/actually/path";

    dbus_util_message_context_add_string(ctx, str_out);
    dbus_util_message_context_add_object_path(ctx, obj_out);

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
    const char *str, *obj;

    dbus_message_context *ctx = dbus_util_make_read_context(call);
    CHECKERRN(ctx != NULL);

    CHECKERR(dbus_util_message_context_get_string(ctx, &str));
    CHECKERR(dbus_util_message_context_get_object_path(ctx, &obj));

    dbus_util_message_context_free(ctx);

    CHECKERRN(!strcmp(str, "funny string test") && !strcmp(obj, "/also/just/funny/string/but/actually/path"));

    ctx = dbus_util_make_reply_context(call);

    const char *str_out = "Another funky string\n!", *obj_out = "/not/very/long/object";

    dbus_util_message_context_add_string(ctx, str_out);
    dbus_util_message_context_add_object_path(ctx, obj_out);

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
    CHECKERR(dbus_util_create_bus_with_name(&bus, "me.quartzy.dbusutil.teststr"));
    FILE *fp = fopen("test_str.xml", "r");
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
            dbus_util_find_interface(dbus_util_find_object(bus, "/"), "me.quartzy.dbusutil.teststr"), "Test", method_cb,
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