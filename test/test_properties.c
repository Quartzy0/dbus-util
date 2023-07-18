#include "dbus-util.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define CHECKERR(x) do{int ret = (x);if(ret != 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)
#define CHECKERRN(x) do{int ret = (x);if(ret == 0){printf("Assert fail in %s:%d with %d\n", __FILE__, __LINE__, ret);dbus_util_free_bus(bus);exit(1);}}while(0)

void
send_set_property_method(dbus_bus *bus, const char *name, dbus_util_method_reply_callback cb,
                         dbus_util_property_get_callback cb1);

bool running;
int ready_fd[2];

int prop_count;

void check_prop_count(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    if (--prop_count == 0) {
        dbus_method_call *call = dbus_util_new_method_call("me.quartzy.dbusutil.testproperties", "/",
                                                           "me.quartzy.dbusutil.testproperties", "AllRead");

        CHECKERR(dbus_util_send_method(bus, call, NULL, NULL));
        dbus_util_free_method_call(call);
        running = false;
    }
}

void
test_set_prop_int(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "i"));
    dbus_util_message_context_add_int32(ctx, 11111);
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
}

void
test_prop_int(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    int32_t i;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "i"));
    CHECKERR(dbus_util_message_context_get_int32(ctx, &i));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(i == 45465);
    send_set_property_method(bus, "Prop_int", check_prop_count, test_set_prop_int);
}

void
test_set_prop_int1(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "u"));
    dbus_util_message_context_add_uint32(ctx, 22222);
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
}

void
test_prop_int1(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    uint32_t i;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "u"));
    CHECKERR(dbus_util_message_context_get_uint32(ctx, &i));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(i == 21123);
    send_set_property_method(bus, "Prop_int1", check_prop_count, test_set_prop_int1);
}

void
test_set_prop_str(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "s"));
    dbus_util_message_context_add_string(ctx, "String but changed");
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
}

void
test_prop_str(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    const char *s;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "s"));
    CHECKERR(dbus_util_message_context_get_string(ctx, &s));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(!strcmp(s, "string property test"));
    send_set_property_method(bus, "Prop_str", check_prop_count, test_set_prop_str);
}

void
test_set_prop_complex(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "(so)"));
    CHECKERR(dbus_util_message_context_enter_struct(&ctx));
    dbus_util_message_context_add_string(ctx, "Also funny changed");
    dbus_util_message_context_add_object_path(ctx, "/very/different/now");
    CHECKERR(dbus_util_message_context_exit_struct(&ctx));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
}

void
test_prop_complex(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    const char *str, *obj;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "(so)"));
    CHECKERR(dbus_util_message_context_enter_struct(&ctx));
    CHECKERR(dbus_util_message_context_get_string(ctx, &str));
    CHECKERR(dbus_util_message_context_get_object_path(ctx, &obj));
    CHECKERR(dbus_util_message_context_exit_struct(&ctx));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(!strcmp(str, "string property test complex") && !strcmp(obj, "/object/property/test/complex"));
    send_set_property_method(bus, "Prop_complex", check_prop_count, test_set_prop_complex);
}

void
test_prop_bool(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    bool b;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "b"));
    CHECKERR(dbus_util_message_context_get_bool(ctx, &b));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(b == false);
    check_prop_count(bus, NULL, NULL);
}

void
test_prop_str_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    const char *s;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "s"));
    CHECKERR(dbus_util_message_context_get_string(ctx, &s));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    CHECKERRN(!strcmp(s, "string, but callback"));
    check_prop_count(bus, NULL, NULL);
}

void
send_get_property_method(dbus_bus *bus, const char *name, dbus_util_method_reply_callback cb) {
    dbus_method_call *call = dbus_util_new_method_call("me.quartzy.dbusutil.testproperties", "/",
                                                       "org.freedesktop.DBus.Properties", "Get");

    dbus_message_context *ctx = dbus_util_make_write_context(call);

    dbus_util_message_context_add_string(ctx, "me.quartzy.dbusutil.testproperties");
    dbus_util_message_context_add_string(ctx, name);

    dbus_util_message_context_free(ctx);

    CHECKERR(dbus_util_send_method(bus, call, cb, bus));
    dbus_util_free_method_call(call);
}

void
send_set_property_method(dbus_bus *bus, const char *name, dbus_util_method_reply_callback cb,
                         dbus_util_property_get_callback cb1) {
    dbus_method_call *call = dbus_util_new_method_call("me.quartzy.dbusutil.testproperties", "/",
                                                       "org.freedesktop.DBus.Properties", "Set");

    dbus_message_context *ctx = dbus_util_make_write_context(call);

    dbus_util_message_context_add_string(ctx, "me.quartzy.dbusutil.testproperties");
    dbus_util_message_context_add_string(ctx, name);
    cb1(bus, ctx, NULL);

    dbus_util_message_context_free(ctx);

    CHECKERR(dbus_util_send_method(bus, call, cb, bus));
    dbus_util_free_method_call(call);
}

int
child_main() {
    int ready_sig = 0;
    while (ready_sig != 2) {
        read(ready_fd[0], &ready_sig, sizeof(ready_sig));
    }

    dbus_bus *bus;
    dbus_util_create_bus(&bus);

    prop_count = 5;
    send_get_property_method(bus, "Prop_int", test_prop_int);
    send_get_property_method(bus, "Prop_int1", test_prop_int1);
    send_get_property_method(bus, "Prop_str", test_prop_str);
    send_get_property_method(bus, "Prop_complex", test_prop_complex);
    send_get_property_method(bus, "Prop_bool", test_prop_bool);
    send_get_property_method(bus, "Prop_str_cb", test_prop_str_cb);

    while (running) {
        dbus_util_poll_messages(bus);
        usleep(10000);
    }
    dbus_util_free_bus(bus);

    return 0;
}

bool property_ptr = false;
char *com_str = NULL, *com_obj = NULL;

void
all_read_cb(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call, void *param) {
    CHECKERRN(dbus_util_get_property_int32(interface, "Prop_int") == 11111);
    CHECKERRN(dbus_util_get_property_uint32(interface, "Prop_int1") == 22222);
    CHECKERRN(!strcmp(dbus_util_get_property_string(interface, "Prop_str"), "String but changed"));
    CHECKERRN(!strcmp(com_str, "Also funny changed"));
    CHECKERRN(!strcmp(com_obj, "/very/different/now"));
    CHECKERRN(property_ptr == false);

    running = false;
}

void complex_property_get_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "(so)"));
    CHECKERR(dbus_util_message_context_enter_struct(&ctx));
    dbus_util_message_context_add_string(ctx, com_str);
    dbus_util_message_context_add_object_path(ctx, com_obj);
    CHECKERR(dbus_util_message_context_exit_struct(&ctx));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
}

void complex_property_set_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    const char *str, *obj;
    CHECKERR(dbus_util_message_context_enter_variant(&ctx, "(so)"));
    CHECKERR(dbus_util_message_context_enter_struct(&ctx));
    CHECKERR(dbus_util_message_context_get_string(ctx, &str));
    CHECKERR(dbus_util_message_context_get_object_path(ctx, &obj));
    CHECKERR(dbus_util_message_context_exit_struct(&ctx));
    CHECKERR(dbus_util_message_context_exit_variant(&ctx));
    free(com_str);
    com_str = strdup(str);
    free(com_obj);
    com_obj = strdup(obj);
}

void Prop_str_cb(dbus_bus *bus, dbus_message_context *ctx, void *param) {
    dbus_util_message_context_add_string_variant(ctx, "string, but callback");
}

void *init_lock(void *param){
    pthread_mutex_t *mutex = malloc(sizeof(*mutex));
    return mutex;
}

void free_lock(void *lock){
    pthread_mutex_destroy(lock);
    free(lock);
}

int
main() {
    running = true;
    if (pipe(ready_fd)) {
        perror("error when calling pipe");
        return 1;
    }
    if (!fork()) {
        return child_main();
    }
    com_str = strdup("string property test complex");
    com_obj = strdup("/object/property/test/complex");

    dbus_bus *bus;
    CHECKERR(dbus_util_create_bus_with_name(&bus, "me.quartzy.dbusutil.testproperties"));

    dbus_util_set_lock_cb(bus, init_lock, (dbus_util_lock_callback) pthread_mutex_lock,
                          (dbus_util_unlock_callback) pthread_mutex_unlock,
                          free_lock, NULL);

    FILE *fp = fopen("test_properties.xml", "r");
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    rewind(fp);
    char buf[len + 1];
    fread(buf, len, sizeof(*buf), fp);
    fclose(fp);
    buf[len] = 0;
    CHECKERR(dbus_util_set_introspectable_xml(bus, buf));
    CHECKERR(dbus_util_parse_introspection(bus));
    CHECKERR(dbus_util_add_property_interface(dbus_util_find_object(bus, "/")));

    dbus_interface *interface = dbus_util_find_interface(dbus_util_find_object(bus, "/"),
                                                         "me.quartzy.dbusutil.testproperties");
    dbus_util_set_property(interface, "Prop_int", 45465);
    dbus_util_set_property(interface, "Prop_int1", 21123);
    dbus_util_set_property(interface, "Prop_str", "string property test");
    dbus_util_set_property_cb(interface, "Prop_complex", complex_property_get_cb, complex_property_set_cb, NULL);
    dbus_util_set_property_ptr(interface, "Prop_bool", &property_ptr);
    dbus_util_set_property_cb(interface, "Prop_str_cb", Prop_str_cb, NULL, NULL);

    dbus_util_set_method_cb(interface, "AllRead", all_read_cb, NULL);

    int ready_sig = 2;
    write(ready_fd[1], &ready_sig, sizeof(ready_sig));

    while (running) {
        dbus_util_poll_messages(bus);
        usleep(10000);
    }
    dbus_util_free_bus(bus);
    free(com_str);
    free(com_obj);

    return 0;
}