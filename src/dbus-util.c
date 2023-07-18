#include "dbus-util.h"
#include "vec.h"

#include <dbus/dbus.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <libxml/xmlreader.h>

#define FREE_ERROR_MSG(new) if(bus->error_msg_need_free)free(bus->error_msg);bus->error_msg_need_free=(new)
#define RETURN_ERROR(x, msg) FREE_ERROR_MSG(false);bus->error_msg=(msg);bus->error=(x);goto error
#define CHECK_DBUS_ERROR() do{if(dbus_error_is_set(&bus->err) && bus->err.message){FREE_ERROR_MSG(true);bus->error_msg=strdup(bus->err.message);bus->error=DBUS_UTIL_DBUS_ERROR;dbus_error_free(&bus->err);goto error;}}while(0)

#define ASSERT(x, y) do{if(!(x)){RETURN_ERROR(y,"Assert '" #x "' failed");}}while(0)
#define ASSERTD(x) do{if(!(x)){RETURN_ERROR(DBUS_UTIL_ASSERT_FAIL,"Assert '" #x "' failed");}}while(0)

static const char null_str[] = "(null)";
static const char null_obj[] = "/null";

struct dbus_lock_cb{
    bool lock_set;
    dbus_util_create_lock_callback create_lock;
    dbus_util_lock_callback lock;
    dbus_util_unlock_callback unlock;
    dbus_util_free_lock_callback free;
    void *param;
};

struct dbus_message_context_t {
    DBusMessageIter msg_iter;
    int container_type;
    bool read: 1;
    bool first_read: 1;
    struct dbus_message_context_t *parent;
};

struct dbus_method_call_t {
    DBusMessage *msg;
    DBusMessage *reply;
    dbus_uint32_t serial;
};

struct dbus_method_return_cb_t {
    dbus_uint32_t serial;
    dbus_util_method_reply_callback cb;
    void *param;
};

struct dbus_interface_t {
    char *name;
    struct dbus_lock_cb *lock_cb;
    struct dbus_method_t {
        char *name;
        dbus_util_method_callback cb;
        void *param;
    } *methods;
    size_t methods_len;
    size_t methods_size;

    struct dbus_property_t {
        char *name;
        bool complex: 1;
        bool ptr: 1;
        bool changed: 1; // If set it will be included in the PropertiesChanged signal
        bool settable: 1;
        int type; // Not defined if complex is true
        void *param; // Only used if complex is true
        void *lock; // Only used if not complex and not pointer
        dbus_util_property_set_callback set_cb; // Only used if complex and settable are true
        union {
            dbus_bool_t boolean;
            int8_t int8;
            dbus_int16_t int16;
            dbus_uint16_t uint16;
            dbus_int32_t int32;
            dbus_uint32_t uint32;
            dbus_int64_t int64;
            dbus_uint64_t uint64;
            double dbl;
            char *str;
            void *ptr;
            dbus_util_property_get_callback cb; // Only used if complex is true
        } property_value;
    } *properties;
    size_t properties_len;
    size_t properties_size;
};

struct dbus_object_t {
    char *name;

    dbus_interface *interfaces;
    size_t interfaces_len;
    size_t interfaces_size;

    struct dbus_lock_cb *lock_cb;
};

struct dbus_bus_t {
    bool init: 1;
    bool not_named: 1;
    DBusError err;
    DBusConnection *conn;

    struct dbus_object_t *objects;
    size_t objects_len;
    size_t objects_size;

    struct vec reply_vec;

    const char *introspection_data; // MUST BE NULL-TERMINATED

    struct dbus_lock_cb lock_cb;

    enum dbus_util_error_code error;
    char *error_msg;
    bool error_msg_need_free;
};





// --   Utility functions   --

dbus_object *
dbus_util_find_object(const dbus_bus *bus, const char *name) {
    if (!bus) return NULL;
    for (int i = 0; i < bus->objects_len; ++i) {
        if (!strcmp(bus->objects[i].name, name)) return &bus->objects[i];
    }
    return NULL;
}

dbus_interface *
dbus_util_find_interface(const dbus_object *object, const char *name) {
    if (!object) return NULL;
    for (int i = 0; i < object->interfaces_len; ++i) {
        if (!strcmp(object->interfaces[i].name, name)) return &object->interfaces[i];
    }
    return NULL;
}

struct dbus_method_t *
dbus_util_find_method(const dbus_interface *interface, const char *name) {
    if (!interface) return NULL;
    for (int i = 0; i < interface->methods_len; ++i) {
        if (!strcmp(interface->methods[i].name, name)) return &interface->methods[i];
    }
    return NULL;
}

struct dbus_property_t *
dbus_util_find_property(const dbus_interface *interface, const char *name) {
    if (!interface) return NULL;
    for (int i = 0; i < interface->properties_len; ++i) {
        if (!strcmp(interface->properties[i].name, name)) return &interface->properties[i];
    }
    return NULL;
}

int
dbus_util_create_property_message(dbus_bus *bus, dbus_message_context *ctx, struct dbus_property_t *p);

int
dbus_util_send_error_reply_generic(dbus_method_call *method_call, const char *error_name, const char *error_message) {
    if (!method_call->msg) return DBUS_UTIL_INVALID_ARGUMENTS;

    if (!method_call->reply) method_call->reply = dbus_message_new_error(method_call->msg, error_name, error_message);

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_message_context_enter_container(dbus_message_context **ctx, const char *container_sig, int type) {
    if (!ctx || !(*ctx)) return DBUS_UTIL_INVALID_ARGUMENTS;

    dbus_message_context *context = malloc(sizeof(*context));
    if (!context) {
        perror("Error when calling mallloc");
        return DBUS_UTIL_ERR_MEM;
    }
    context->parent = *ctx;
    context->container_type = type;
    context->read = (*ctx)->read;

    if ((*ctx)->read) {
        if (!(*ctx)->first_read && !dbus_message_iter_next(&(*ctx)->msg_iter)) {
            free(context);
            return DBUS_UTIL_DBUS_ERROR;
        }
        if (dbus_message_iter_get_arg_type(&(*ctx)->msg_iter) != type) {
            free(context);
            return DBUS_UTIL_BAD_TYPE;
        }
        (*ctx)->first_read = false;
        dbus_message_iter_recurse(&(*ctx)->msg_iter, &context->msg_iter);
        context->first_read = true;
        if (container_sig) {
            char *sig = dbus_message_iter_get_signature(&context->msg_iter);
            if (strcmp(sig, container_sig) != 0) {
                dbus_free(sig);
                free(context);
                return DBUS_UTIL_BAD_TYPE;
            }
            dbus_free(sig);
        }
    } else {
        if (!dbus_message_iter_open_container(&(*ctx)->msg_iter, type, container_sig, &context->msg_iter)) {
            fprintf(stderr, "[dbus-util] DBus out of memory error\n");
            free(context);
            return DBUS_UTIL_ERR_MEM;
        }
    }

    *ctx = context;
    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_message_context_exit_container(dbus_message_context **ctx, int type) {
    if (!ctx || !(*ctx) || !(*ctx)->parent) return DBUS_UTIL_INVALID_ARGUMENTS;
    if ((*ctx)->container_type != type) {
        fprintf(stderr, "Trying to close container type %c on context with type %c\n", type, (*ctx)->container_type);
        return DBUS_UTIL_INCORRECT_CLOSE;
    }

    dbus_message_context *parent = (*ctx)->parent;
    if (!(*ctx)->read) {
        if (!dbus_message_iter_close_container(&parent->msg_iter, &(*ctx)->msg_iter)) {
            fprintf(stderr, "[dbus-util] DBus out of memory error\n");
            return DBUS_UTIL_ERR_MEM;
        }
    }
    free(*ctx);
    *ctx = parent;

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_add_new_property(dbus_interface *interface, const char *name, struct dbus_property_t **out) {
    if (!interface || !name || !out) return DBUS_UTIL_INVALID_ARGUMENTS;

    for (int i = 0; i < interface->properties_len; ++i) {
        if (!strcmp(interface->properties[i].name, name)) {
            *out = &interface->properties[i];
            return DBUS_UTIL_SUCCESS;
        }
    }

    if (interface->properties_len >= interface->properties_size) {
        interface->properties_size *= 2;
        struct dbus_property_t *properties_tmp = realloc(interface->properties,
                                                         interface->properties_size * sizeof(*interface->properties));
        if (!properties_tmp) {
            perror("Error when calling realloc");
            return DBUS_UTIL_ERR_MEM;
        }
        interface->properties = properties_tmp;
    }

    struct dbus_property_t *property = &interface->properties[interface->properties_len++];
    memset(property, 0, sizeof(*property));
    property->name = strdup(name);
    if (interface->lock_cb->lock_set) property->lock = interface->lock_cb->create_lock(interface->lock_cb->param);

    *out = property;

    return DBUS_UTIL_SUCCESS;
}




// --       API             --

/*      Initialization functions        */

int
dbus_util_create_bus(dbus_bus **bus_out) {
    dbus_bus *bus = ((*bus_out) = malloc(sizeof(**bus_out)));
    ASSERT(bus != NULL, DBUS_UTIL_ERR_MEM);
    memset(bus, 0, sizeof(*bus));

    dbus_error_init(&bus->err);

    bus->conn = dbus_bus_get(DBUS_BUS_SESSION, &bus->err);
    CHECK_DBUS_ERROR();
    ASSERT(bus->conn != NULL, DBUS_UTIL_DBUS_ERROR);

    bus->init = true;
    bus->not_named = true;

    vec_init(&bus->reply_vec);

    return bus->error;

    error:
    if (bus) dbus_error_free(&bus->err);
    free(bus);
    return DBUS_UTIL_ASSERT_FAIL;
}

int
dbus_util_create_bus_with_name(dbus_bus **bus_out, const char *name) {
    int ret = dbus_util_create_bus(bus_out);
    if (ret) return ret;
    dbus_bus *bus = *bus_out;

    int name_request = dbus_bus_request_name(bus->conn, name, DBUS_NAME_FLAG_REPLACE_EXISTING, &bus->err);
    CHECK_DBUS_ERROR();
    ASSERT(name_request == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER, DBUS_UTIL_DBUS_ERROR);

    bus->objects_len = 0;
    bus->objects_size = 1;
    bus->objects = malloc(bus->objects_size * sizeof(*bus->objects));

    bus->not_named = false;

    return bus->error;

    error:
    if (bus) dbus_error_free(&bus->err);
    free(bus);
    return DBUS_UTIL_ASSERT_FAIL;
}

void
dbus_util_free_bus(dbus_bus *bus) {
    if (!bus) return;
    if (bus->error_msg && bus->error_msg_need_free) free(bus->error_msg);
    dbus_error_free(&bus->err);
    for (int k = 0; k < bus->objects_len; ++k) {
        struct dbus_object_t *object = &bus->objects[k];
        for (int i = 0; i < object->interfaces_len; ++i) {
            dbus_interface *interface = &object->interfaces[i];
            for (int j = 0; j < interface->methods_len; ++j) {
                free(interface->methods[j].name);
            }
            free(interface->methods);
            for (int j = 0; j < interface->properties_len; ++j) {
                free(interface->properties[j].name);
                if (!interface->properties[j].ptr && !interface->properties[j].complex &&
                    (interface->properties[j].type == DBUS_TYPE_STRING ||
                     interface->properties[j].type == DBUS_TYPE_OBJECT_PATH)) {
                    free(interface->properties[j].property_value.str);
                }
                if (bus->lock_cb.lock_set && bus->lock_cb.free && interface->properties[j].lock) bus->lock_cb.free(interface->properties[j].lock);
            }
            free(interface->properties);

            free(interface->name);
        }
        free(object->name);
        free(object->interfaces);
    }
    free(bus->objects);
    for (int i = 0; i < bus->reply_vec.len; ++i) {
        free(bus->reply_vec.el[i]);
    }
    vec_free(&bus->reply_vec);
    dbus_connection_unref(bus->conn);
    memset(bus, 0, sizeof(*bus));
    free(bus);
}

dbus_object *
dbus_util_add_object(dbus_bus *bus, const char *name) {
    if (!bus || !name || bus->not_named) return NULL;

    dbus_object *object = dbus_util_find_object(bus, name);
    if (object) return NULL;

    if (bus->objects_len >= bus->objects_size) {
        bus->objects_size *= 2;
        dbus_object *objects_tmp = realloc(bus->objects, bus->objects_size * sizeof(*objects_tmp));
        if (!objects_tmp) {
            perror("Error when calling realloc");
            return NULL;
        }
        bus->objects = objects_tmp;
    }
    object = &bus->objects[bus->objects_len++];
    object->name = strdup(name);

    object->interfaces_size = 1;
    object->interfaces_len = 0;
    object->interfaces = malloc(object->interfaces_size * sizeof(*object->interfaces));
    object->lock_cb = &bus->lock_cb;

    return object;
}

const char *
dbus_util_get_error(dbus_bus *bus) {
    return bus->error_msg;
}

dbus_interface *
dbus_util_add_interface(dbus_object *object, const char *name) {
    if (!name) return NULL;

    dbus_interface *interface = dbus_util_find_interface(object, name);
    if (interface) return NULL;

    if (object->interfaces_len >= object->interfaces_size) {
        object->interfaces_size *= 2;
        dbus_interface *interfaces_tmp = realloc(object->interfaces, object->interfaces_size * sizeof(*interfaces_tmp));
        if (!interfaces_tmp) {
            perror("Error when calling realloc");
            return NULL;
        }
        object->interfaces = interfaces_tmp;
    }
    interface = &object->interfaces[object->interfaces_len++];
    interface->name = strdup(name);

    interface->methods_size = 1;
    interface->methods_len = 0;
    interface->methods = malloc(interface->methods_size * sizeof(*interface->methods));

    interface->properties_size = 1;
    interface->properties_len = 0;
    interface->properties = malloc(interface->properties_size * sizeof(*interface->properties));
    interface->lock_cb = object->lock_cb;

    return &object->interfaces[object->interfaces_len - 1];
}

int
dbus_util_add_method(dbus_interface *interface, const char *name) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;

    struct dbus_method_t *method = dbus_util_find_method(interface, name);
    if (method) return DBUS_UTIL_ALREADY_EXISTS;

    if (interface->methods_len >= interface->methods_size) {
        interface->methods_size *= 2;
        struct dbus_method_t *methods_tmp = realloc(interface->methods, interface->methods_size * sizeof(*methods_tmp));
        if (!methods_tmp) {
            perror("Error when calling realloc");
            return DBUS_UTIL_ERR_MEM;
        }
        interface->methods = methods_tmp;
    }
    method = &interface->methods[interface->methods_len++];
    method->name = strdup(name);
    if (!method->name) return DBUS_UTIL_ERR_MEM;

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_set_method_cb(dbus_interface *interface, const char *name, dbus_util_method_callback cb, void *param) {
    if (!interface || !name || !cb) return DBUS_UTIL_INVALID_ARGUMENTS;

    struct dbus_method_t *method = dbus_util_find_method(interface, name);
    if (!method) return DBUS_UTIL_INVALID_ARGUMENTS;

    method->cb = cb;
    method->param = param;
    return DBUS_UTIL_SUCCESS;
}

void
dbus_util_set_lock_cb(dbus_bus *bus, dbus_util_create_lock_callback create, dbus_util_lock_callback lock, dbus_util_unlock_callback unlock, dbus_util_free_lock_callback free, void *param){
    if (!bus) return;

    bus->lock_cb.create_lock = create;
    bus->lock_cb.lock = lock;
    bus->lock_cb.unlock = unlock;
    bus->lock_cb.free = free;
    bus->lock_cb.lock_set = true;
}

void
dbus_util_poll_messages(dbus_bus *bus) {
    if (!bus || !bus->init) return;

    while (true) {
        dbus_connection_read_write(bus->conn, 0);
        DBusMessage *msg = dbus_connection_pop_message(bus->conn);
        if (!msg) return;

        dbus_method_call method_call = {
                .msg = msg,
                .serial = dbus_message_get_serial(msg),
                .reply = NULL,
        };

        dbus_uint32_t reply_serial = dbus_message_get_reply_serial(msg);
        for (int i = 0; i < bus->reply_vec.len; ++i) {
            if (((struct dbus_method_return_cb_t *) bus->reply_vec.el[i])->serial == reply_serial) {
                struct dbus_method_return_cb_t *c = (struct dbus_method_return_cb_t *) bus->reply_vec.el[i];

                dbus_message_context *ctx = dbus_util_make_read_context(&method_call);
                c->cb(bus, ctx, c->param);
                dbus_util_message_context_free(ctx);

                free(c);
                vec_remove_index(&bus->reply_vec, i);
                dbus_message_unref(msg);
                return;
            }
        }

        const char *object_path = dbus_message_get_path(msg);
        const char *interface_name = dbus_message_get_interface(msg);
        const char *member = dbus_message_get_member(msg);

        if (!object_path || !interface_name || !member) return;
        struct dbus_object_t *object = dbus_util_find_object(bus, object_path);
        struct dbus_interface_t *interface = dbus_util_find_interface(object, interface_name);
        struct dbus_method_t *method = dbus_util_find_method(interface, member);

        if (!interface || !method) {
            dbus_message_unref(msg);
            return;
        }


        if (method->cb) method->cb(bus, object, interface, &method_call, method->param);

        if (method_call.reply) {
            if (!dbus_connection_send(bus->conn, method_call.reply, &method_call.serial)) {
                fprintf(stderr, "[dbus-util] DBus out of memory error\n");
            }
            dbus_message_unref(method_call.reply);
            method_call.reply = NULL;
        }

        dbus_message_unref(msg);
    }
}

// Emits org.freedesktop.DBus.Properties.PropertiesChanged for all interfaces. All complex properties (the ones with a callback)
// are put into the invalidated_properties array instead of the changed_properties dict entry array.
void
dbus_util_emit_signals(dbus_bus *bus) {
    if (!bus || bus->not_named) return;
    dbus_uint32_t serial = 0;

    for (int k = 0; k < bus->objects_len; ++k) {
        dbus_object *object = &bus->objects[k];
        for (int i = 0; i < object->interfaces_len; ++i) {
            dbus_message_context np_ctx = {0}, *ctx;
            np_ctx.read = false;
            DBusMessage *msg = NULL;
            dbus_interface *interface = &object->interfaces[i];
            for (int j = 0; j < interface->properties_len; ++j) {
                struct dbus_property_t *property = &interface->properties[j];
                if (property->changed) {
                    if (!msg) {
                        msg = dbus_message_new_signal(object->name, "org.freedesktop.DBus.Properties",
                                                      "PropertiesChanged");

                        dbus_message_iter_init_append(msg, &np_ctx.msg_iter);
                        np_ctx.parent = NULL;
                        np_ctx.container_type = -1;
                        ctx = &np_ctx;

                        dbus_util_message_context_add_string(ctx, interface->name);
                        dbus_util_message_context_enter_array(&ctx, "{sv}");
                    }
                    if (!property->complex) {
                        dbus_util_message_context_enter_dict_entry(&ctx);
                        dbus_util_message_context_add_string(ctx, property->name);
                        dbus_util_create_property_message(bus, ctx, property);
                        dbus_util_message_context_exit_dict_entry(&ctx);
                        property->changed = false;
                    }
                }
            }
            if (msg) {
                dbus_util_message_context_exit_array(&ctx);
                dbus_util_message_context_enter_array(&ctx, DBUS_TYPE_STRING_AS_STRING);
            }
            for (int j = 0; j < interface->properties_len; ++j) {
                struct dbus_property_t *property = &interface->properties[j];
                if (property->changed) {
                    if (!msg) {
                        msg = dbus_message_new_signal(object->name, "org.freedesktop.DBus.Properties",
                                                      "PropertiesChanged");

                        dbus_message_iter_init_append(msg, &np_ctx.msg_iter);
                        np_ctx.parent = NULL;
                        np_ctx.container_type = -1;
                        ctx = &np_ctx;

                        dbus_util_message_context_add_string(ctx, interface->name);
                        dbus_util_message_context_enter_array(&ctx, "{sv}");
                        dbus_util_message_context_exit_array(&ctx);
                        dbus_util_message_context_enter_array(&ctx, DBUS_TYPE_STRING_AS_STRING);
                    }
                    if (property->complex) {
                        dbus_util_message_context_add_string(ctx, property->name);
                        property->changed = false;
                    }
                }
            }
            if (msg) {
                dbus_util_message_context_exit_array(&ctx);
                if (!dbus_connection_send(bus->conn, msg, &serial)) {
                    fprintf(stderr, "[dbus-util] DBus out of memory error\n");
                }
                dbus_message_unref(msg);
            }
        }
    }
}

/*      Introspectable functions        */

void
dbus_util_properties_introspect(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
                                void *param) {
    dbus_util_add_reply_values(bus, call, DBUS_TYPE_STRING, &bus->introspection_data, DBUS_TYPE_INVALID);
}

int
dbus_util_add_introspectable_interface(dbus_object *object) {
    if (!object) return DBUS_UTIL_INVALID_ARGUMENTS;

    dbus_interface *interface = dbus_util_add_interface(object, "org.freedesktop.DBus.Introspectable");
    if (!interface) return DBUS_UTIL_ASSERT_FAIL;
    dbus_util_add_method(interface, "Introspect");
    dbus_util_set_method_cb(interface, "Introspect", dbus_util_properties_introspect, NULL);

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_set_introspectable_xml(dbus_bus *bus, const char *xml_str) {
    if (!bus || bus->not_named) return DBUS_UTIL_INVALID_ARGUMENTS;
    bus->introspection_data = xml_str;

    return DBUS_UTIL_SUCCESS;
}


int
dbus_util_parse_introspection(dbus_bus *bus) {
    if (!bus || bus->not_named || !bus->introspection_data) return DBUS_UTIL_INVALID_ARGUMENTS;
    int ret;

    size_t size = strlen(bus->introspection_data);
    xmlTextReaderPtr reader = xmlReaderForMemory(bus->introspection_data, (int) size, "introspection.xml", NULL, 0);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        dbus_object *object = NULL;
        dbus_interface *interface = NULL;

        while (ret == 1) {

            const char *name = (const char *) xmlTextReaderConstName(reader);
            int type = xmlTextReaderNodeType(reader);
            if (!strcmp(name, "node")) {
                if (type == XML_ELEMENT_NODE) {
                    if (object != NULL) {
                        fprintf(stderr, "Nested object not yet supported\n");
                        goto error;
                    }
                    char *obj_name = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "name");
                    if (!obj_name) {
                        fprintf(stderr, "<node> tag must have a name attribute\n");
                        goto error;
                    }
                    object = dbus_util_add_object(bus, obj_name);
                    free(obj_name);
                } else if (type == XML_ELEMENT_DECL) {
                    object = NULL;
                }
            } else if (!strcmp(name, "interface")) {
                if (type == XML_ELEMENT_NODE) {
                    if (!object) {
                        fprintf(stderr, "<interface> tag must be inside <node> tag\n");
                        goto error;
                    } else if (interface) {
                        fprintf(stderr, "<interface> tag can't be inside <interface> tag\n");
                        goto error;
                    }
                    char *iface_name = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "name");
                    if (!iface_name) {
                        fprintf(stderr, "<interface> tag must have a name attribute\n");
                        goto error;
                    }
                    interface = dbus_util_add_interface(object, iface_name);
                    free(iface_name);
                } else if (type == XML_ELEMENT_DECL) {
                    interface = NULL;
                }
            } else if (!strcmp(name, "method")) {
                if (type == XML_ELEMENT_NODE) {
                    if (!object || !interface) {
                        fprintf(stderr, "<method> tag must be inside <node> and <interface> tags\n");
                        goto error;
                    }
                    char *method_name = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "name");
                    if (!method_name) {
                        fprintf(stderr, "<method> tag must have a name attribute\n");
                        goto error;
                    }
                    dbus_util_add_method(interface, method_name);
                    free(method_name);
                }
            } else if (!strcmp(name, "property")) {
                if (!object || !interface) {
                    fprintf(stderr, "<property> tag must be inside <node> and <interface> tags\n");
                    goto error;
                }

                char *property_name = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "name");
                char *type_str = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "type");
                char *access_str = (char *) xmlTextReaderGetAttribute(reader, (xmlChar *) "access");

                if (!property_name) {
                    fprintf(stderr, "<property> tag must have a name attribute\n");
                    goto error;
                }
                if (!type_str) {
                    fprintf(stderr, "<property> tag must have a type attribute\n");
                    goto error;
                }
                if (!access_str) {
                    fprintf(stderr, "<property> tag must have an access attribute\n");
                    goto error;
                }

                struct dbus_property_t *p;
                dbus_util_add_new_property(interface, property_name, &p);
                p->complex = strlen(type_str) > 1;
                p->settable = !!strcmp(access_str, "read");
                if (!p->complex) {
                    p->type = (int) type_str[0];
                }

                free(property_name);
                free(type_str);
                free(access_str);

            }


            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);
        if (ret != 0) {
            fprintf(stderr, "[dbus-util] failed to parse introspection\n");
            return DBUS_UTIL_INVALID_ARGUMENTS;
        }
    } else {
        fprintf(stderr, "[dbus-util] failed to parse introspection\n");
        return DBUS_UTIL_INVALID_ARGUMENTS;
    }

    dbus_object *obj = dbus_util_find_object(bus, "/");
    if (!obj){
        dbus_util_add_object(bus, "/");
    }

    return DBUS_UTIL_SUCCESS;

    error:
    xmlFreeTextReader(reader);
    return DBUS_UTIL_ASSERT_FAIL;
}


/*      Property functions              */

int
dbus_util_create_property_message(dbus_bus *bus, dbus_message_context *ctx, struct dbus_property_t *p) {
    if (p->complex && p->property_value.cb) {
        p->property_value.cb(bus, ctx, p->param);
        return 0;
    }

    if (p->ptr) {
        char t = (char) p->type;
        dbus_util_message_context_enter_variant(&ctx, &t);
        dbus_util_message_context_add_basic_ptr(ctx, p->type, p->property_value.ptr);
        dbus_util_message_context_exit_variant(&ctx);
        return 0;
    }

    switch (p->type) {
        case DBUS_TYPE_BOOLEAN:
            dbus_util_message_context_add_bool_variant(ctx, p->property_value.boolean);
            break;
        case DBUS_TYPE_BYTE:
            dbus_util_message_context_add_byte_variant(ctx, p->property_value.int8);
            break;
        case DBUS_TYPE_INT16:
            dbus_util_message_context_add_int16_variant(ctx, p->property_value.int16);
            break;
        case DBUS_TYPE_UINT16:
            dbus_util_message_context_add_uint16_variant(ctx, p->property_value.uint16);
            break;
        case DBUS_TYPE_INT32:
            dbus_util_message_context_add_int32_variant(ctx, p->property_value.int32);
            break;
        case DBUS_TYPE_UINT32:
            dbus_util_message_context_add_uint32_variant(ctx, p->property_value.uint32);
            break;
        case DBUS_TYPE_INT64:
            dbus_util_message_context_add_int64_variant(ctx, p->property_value.int64);
            break;
        case DBUS_TYPE_UINT64:
            dbus_util_message_context_add_uint64_variant(ctx, p->property_value.uint64);
            break;
        case DBUS_TYPE_DOUBLE:
            dbus_util_message_context_add_double_variant(ctx, p->property_value.dbl);
            break;
        case DBUS_TYPE_STRING:
            dbus_util_message_context_add_string_variant(ctx, p->property_value.str);
            break;
        case DBUS_TYPE_OBJECT_PATH:
            dbus_util_message_context_add_object_path_variant(ctx, p->property_value.str);
            break;
        case DBUS_TYPE_UNIX_FD:
            dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_UNIX_FD_AS_STRING);
            dbus_util_message_context_add_fd(ctx, p->property_value.int32);
            dbus_util_message_context_exit_variant(&ctx);
            break;
        default:
            fprintf(stderr, "Invalid type provided for property '%s'.\n", p->name);
            return 1;
    }
    return 0;
}

void
dbus_util_properties_get(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
                         void *param) {
    char *iface, *name;
    if (dbus_util_get_method_arguments(bus, call, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &name,
                                       DBUS_TYPE_INVALID))
        return;

    struct dbus_property_t *p = NULL;
    for (int i = 0; i < object->interfaces_len; ++i) {
        if (!strcmp(object->interfaces[i].name, iface)) {
            dbus_interface *inf = &object->interfaces[i];
            for (int j = 0; j < inf->properties_len; ++j) {
                if (!strcmp(inf->properties[j].name, name)) {
                    p = &inf->properties[j];
                    break;
                }
            }
        }
        if (p) break;
    }
    if (!p) {
        dbus_util_send_error_reply_generic(call, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");
        return;
    }

    dbus_message_context *ctx = dbus_util_make_reply_context(call);
    if (dbus_util_create_property_message(bus, ctx, p)) {
        dbus_util_send_error_reply_generic(call, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");
    }
    dbus_util_message_context_free(ctx);
}

void
dbus_util_properties_get_all(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
                             void *param) {
    char *iface;
    if (dbus_util_get_method_arguments(bus, call, DBUS_TYPE_STRING, &iface, DBUS_TYPE_INVALID))
        return;

    dbus_interface *intf = NULL;
    for (int i = 0; i < object->interfaces_len; ++i) {
        if (!strcmp(object->interfaces[i].name, iface)) {
            intf = &object->interfaces[i];
            break;
        }
    }
    if (!intf) {
        dbus_util_send_error_reply_generic(call, DBUS_ERROR_UNKNOWN_INTERFACE, "Unknown interface");
        return;
    }

    dbus_message_context *ctx = dbus_util_make_reply_context(call);
    dbus_util_message_context_enter_array(&ctx, "{sv}");

    for (int i = 0; i < intf->properties_len; ++i) {
        dbus_util_message_context_enter_dict_entry(&ctx);

        dbus_util_message_context_add_string(ctx, intf->properties[i].name);

        if (dbus_util_create_property_message(bus, ctx, &intf->properties[i])) {
            dbus_util_message_context_add_string_variant(ctx, "(null)");
        }

        dbus_util_message_context_exit_dict_entry(&ctx);
    }

    dbus_util_message_context_exit_array(&ctx);
}

void
dbus_util_properties_set(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
                         void *param) {
    dbus_message_context *ctx = dbus_util_make_read_context(call);

    const char *iface, *name;
    dbus_util_message_context_get_string(ctx, &iface);
    dbus_util_message_context_get_string(ctx, &name);

    struct dbus_property_t *p = NULL;
    for (int i = 0; i < object->interfaces_len; ++i) {
        if (!strcmp(object->interfaces[i].name, iface)) {
            for (int j = 0; j < object->interfaces[i].properties_len; ++j) {
                if (!strcmp(object->interfaces[i].properties[j].name, name)) {
                    p = &object->interfaces[i].properties[j];
                    break;
                }
            }
        }
        if (p) break;
    }
    if (!p || !p->settable) {
        dbus_util_message_context_free(ctx);
        dbus_util_send_error_reply_generic(call, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");
        return;
    }


    if (p->complex) {
        if (p->set_cb) {
            p->set_cb(bus, ctx, p->param);
            p->changed = true;
        } else {
            dbus_util_message_context_free(ctx);
            dbus_util_send_error_reply_generic(call, DBUS_ERROR_UNKNOWN_PROPERTY, "Unknown property");
            return;
        }
    } else {
        dbus_util_message_context_enter_variant(&ctx, NULL);
        switch (p->type) {
            case DBUS_TYPE_BOOLEAN: {
                dbus_bool_t b;
                dbus_util_message_context_get_basic_ptr(ctx, p->type, &b);
                if (p->ptr) *((bool *) p->property_value.ptr) = (bool) b;
                else p->property_value.boolean = b;
                break;
            }
            case DBUS_TYPE_BYTE:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.int8);
                break;
            case DBUS_TYPE_INT16:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.int16);
                break;
            case DBUS_TYPE_UINT16:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.uint16);
                break;
            case DBUS_TYPE_INT32:
            case DBUS_TYPE_UNIX_FD:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.int32);
                break;
            case DBUS_TYPE_UINT32:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.uint32);
                break;
            case DBUS_TYPE_INT64:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.int64);
                break;
            case DBUS_TYPE_UINT64:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.uint64);
                break;
            case DBUS_TYPE_DOUBLE:
                dbus_util_message_context_get_basic_ptr(ctx, p->type,
                                                        p->ptr ? p->property_value.ptr : &p->property_value.dbl);
                break;
            case DBUS_TYPE_STRING:
            case DBUS_TYPE_OBJECT_PATH: {
                char *s;
                dbus_util_message_context_get_basic_ptr(ctx, p->type, &s);
                if (p->ptr) {
                    free(*((char **) p->property_value.ptr));
                    *((char **) p->property_value.ptr) = strdup(s);
                } else {
                    free(p->property_value.str);
                    p->property_value.str = strdup(s);
                }
                break;
            }
            default:
                fprintf(stderr, "[dbus-util] Property '%s' has invalid type %c\n", name, p->type);
                break;
        }
        p->changed = true;
        dbus_util_message_context_exit_variant(&ctx);
    }

    dbus_util_message_context_free(ctx);

    dbus_util_send_empty_reply(call);
}


int
dbus_util_add_property_interface(dbus_object *object) {
    if (!object) return DBUS_UTIL_INVALID_ARGUMENTS;

    dbus_interface *i = dbus_util_add_interface(object, "org.freedesktop.DBus.Properties");
    if (!i) return DBUS_UTIL_ASSERT_FAIL;
    dbus_util_add_method(i, "Get");
    dbus_util_add_method(i, "GetAll");
    dbus_util_add_method(i, "Set");
    dbus_util_set_method_cb(i, "Get", dbus_util_properties_get, NULL);
    dbus_util_set_method_cb(i, "GetAll", dbus_util_properties_get_all, NULL);
    dbus_util_set_method_cb(i, "Set", dbus_util_properties_set, NULL);

    return DBUS_UTIL_SUCCESS;
}

#define PROPERTY_ADD_CONST(v, t) struct dbus_property_t *p; \
                                if (!(p = dbus_util_find_property(interface, name))) return DBUS_UTIL_INVALID_ARGUMENTS;\
                                if(p->complex){\
                                    fprintf(stderr, "Trying to set property '%s' to a value when it is already a complex property\n", name);\
                                    return DBUS_UTIL_INVALID_ARGUMENTS;\
                                }\
                                if(interface->lock_cb->lock_set) interface->lock_cb->lock(p->lock);\
                                p->changed = true;\
                                p->property_value.v = val;  \
                                if(interface->lock_cb->lock_set) interface->lock_cb->unlock(p->lock);\
                                return DBUS_UTIL_SUCCESS

int
dbus_util_set_property_bool(dbus_interface *interface, const char *name, bool val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(boolean, DBUS_TYPE_BOOLEAN);
}

int
dbus_util_add_property_byte(dbus_interface *interface, const char *name, int8_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(int8, DBUS_TYPE_BYTE);
}

int
dbus_util_set_property_int16(dbus_interface *interface, const char *name, int16_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(int16, DBUS_TYPE_INT16);
}

int
dbus_util_set_property_uint16(dbus_interface *interface, const char *name, uint16_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(uint16, DBUS_TYPE_UINT16);
}

int
dbus_util_set_property_int32(dbus_interface *interface, const char *name, int32_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(int32, DBUS_TYPE_INT32);
}

int
dbus_util_set_property_uint32(dbus_interface *interface, const char *name, uint32_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(uint32, DBUS_TYPE_UINT32);
}

int
dbus_util_set_property_int64(dbus_interface *interface, const char *name, int64_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(int64, DBUS_TYPE_INT64);
}

int
dbus_util_set_property_uint64(dbus_interface *interface, const char *name, uint64_t val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(uint64, DBUS_TYPE_UINT64);
}

int
dbus_util_set_property_double(dbus_interface *interface, const char *name, double val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    PROPERTY_ADD_CONST(dbl, DBUS_TYPE_DOUBLE);
}

int
dbus_util_set_property_string(dbus_interface *interface, const char *name, const char *val) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    struct dbus_property_t *p;
    if (!(p = dbus_util_find_property(interface, name))) return DBUS_UTIL_INVALID_ARGUMENTS;
    if (p->complex) {
        fprintf(stderr, "Trying to set property '%s' to a value when it is already a complex property\n", name);
        return DBUS_UTIL_INVALID_ARGUMENTS;
    }
    if(interface->lock_cb->lock_set) interface->lock_cb->lock(p->lock);
    p->changed = true;
    free(p->property_value.str);
    p->property_value.str = strdup(val);
    if(interface->lock_cb->lock_set) interface->lock_cb->unlock(p->lock);

    return DBUS_UTIL_SUCCESS;
}

#define RETURN_PROP(val, t) struct dbus_property_t *p = dbus_util_find_property(interface, name);\
                            if (!p) {\
                                return 0;\
                            }\
                            if (p->type != t){\
                                fprintf(stderr, "[dbus-util] Trying to get property '%s' as %c when it is type %c\n", name, t, p->type);\
                                return 0;\
                            }\
                            if (p->ptr || p->complex){\
                                fprintf(stderr, "[dbus-util] Trying to get property '%s' as %c when it is a pointer/complex\n", name, t);\
                                return 0;\
                            }\
                            return p->property_value.val

bool
dbus_util_get_property_bool(dbus_interface *interface, const char *name) {
    RETURN_PROP(boolean, DBUS_TYPE_BOOLEAN);
}

int8_t
dbus_util_get_property_byte(dbus_interface *interface, const char *name) {
    RETURN_PROP(int8, DBUS_TYPE_BYTE);
}

int16_t
dbus_util_get_property_int16(dbus_interface *interface, const char *name) {
    RETURN_PROP(int16, DBUS_TYPE_INT16);
}

uint16_t
dbus_util_get_property_uint16(dbus_interface *interface, const char *name) {
    RETURN_PROP(uint16, DBUS_TYPE_UINT16);
}

int32_t
dbus_util_get_property_int32(dbus_interface *interface, const char *name) {
    RETURN_PROP(int32, DBUS_TYPE_INT32);
}

uint32_t
dbus_util_get_property_uint32(dbus_interface *interface, const char *name) {
    RETURN_PROP(uint32, DBUS_TYPE_UINT32);
}

int64_t
dbus_util_get_property_int64(dbus_interface *interface, const char *name) {
    RETURN_PROP(int64, DBUS_TYPE_INT64);
}

uint64_t
dbus_util_get_property_uint64(dbus_interface *interface, const char *name) {
    RETURN_PROP(uint64, DBUS_TYPE_UINT64);
}

double
dbus_util_get_property_double(dbus_interface *interface, const char *name) {
    RETURN_PROP(dbl, DBUS_TYPE_DOUBLE);
}

const char *
dbus_util_get_property_string(dbus_interface *interface, const char *name) {
    RETURN_PROP(str, DBUS_TYPE_STRING);
}

int
dbus_util_set_property_ptr(dbus_interface *interface, const char *name, void *ptr) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    struct dbus_property_t *p;
    if (!(p = dbus_util_find_property(interface, name))) return DBUS_UTIL_INVALID_ARGUMENTS;
    if (p->complex) {
        fprintf(stderr, "Trying to set property '%s' to a value when it is already a complex property\n", name);
        return DBUS_UTIL_INVALID_ARGUMENTS;
    }
    if (p->settable) {
        fprintf(stderr, "Can't set a pointer for property '%s' because it is defined as read/write\n", name);
        return DBUS_UTIL_INVALID_ARGUMENTS;
    }
    p->changed = true;
    p->ptr = true;
    p->property_value.ptr = ptr;

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_set_property_cb(dbus_interface *interface, const char *name, dbus_util_property_get_callback get_cb,
                          dbus_util_property_set_callback set_cb, void *userp) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    struct dbus_property_t *p;
    int ret;
    if ((ret = dbus_util_add_new_property(interface, name, &p)))return ret;
    if (!get_cb) {
        fprintf(stderr, "[dbus-util] The get callback was set to NULL for property '%s'\n", name);
    }
    if (p->settable && !set_cb) {
        fprintf(stderr, "[dbus-util] The set callback was set to NULL for property '%s', which is settable", name);
    }
    p->param = userp;
    p->changed = true;
    p->complex = true;
    p->property_value.cb = get_cb;
    p->set_cb = set_cb;

    return ret;
}

int
dbus_util_invalidate_property(dbus_interface *interface, const char *name) {
    if (!interface || !name) return DBUS_UTIL_INVALID_ARGUMENTS;
    struct dbus_property_t *property = dbus_util_find_property(interface, name);
    if (!property) return DBUS_UTIL_INVALID_ARGUMENTS;
    property->changed = true;
    return DBUS_UTIL_SUCCESS;
}


/*      Quick argument functions        */

int
dbus_util_get_method_arguments(dbus_bus *bus, dbus_method_call *method_call, int first, ...) {
    if (!bus || !bus->init) return DBUS_UTIL_ASSERT_FAIL;
    ASSERTD(method_call != NULL);
    bus->error = DBUS_UTIL_SUCCESS;

    va_list list;
    va_start(list, first);

    if (!dbus_message_get_args_valist(method_call->msg, &bus->err, first, list)) {
        va_end(list);
        if (dbus_error_is_set(&bus->err)) {
            dbus_util_send_error_reply_generic(method_call, bus->err.name, bus->err.message);
            dbus_error_free(&bus->err);
            return DBUS_UTIL_INVALID_ARGUMENTS;
        }
    }

    va_end(list);

    error:
    return bus->error;
}

int
dbus_util_add_reply_values(dbus_bus *bus, dbus_method_call *method_call, int first, ...) {
    if (!bus || !bus->init) return DBUS_UTIL_ASSERT_FAIL;
    ASSERTD(method_call != NULL);
    bus->error = DBUS_UTIL_SUCCESS;

    if (!method_call->reply) method_call->reply = dbus_message_new_method_return(method_call->msg);

    va_list list;
    va_start(list, first);

    if (!dbus_message_append_args_valist(method_call->reply, first, list)) {
        va_end(list);
        if (dbus_error_is_set(&bus->err)) {
            dbus_error_free(&bus->err);
            return DBUS_UTIL_INVALID_ARGUMENTS;
        }
    }

    va_end(list);

    error:
    return bus->error;
}

int
dbus_util_send_empty_reply(dbus_method_call *method_call) {
    if (!method_call->reply) method_call->reply = dbus_message_new_method_return(method_call->msg);

    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_send_error_reply(dbus_method_call *method_call, const char *error) {
    return dbus_util_send_error_reply_generic(method_call, DBUS_ERROR_FAILED, error);
}

void
dbus_util_message_context_free(dbus_message_context *ctx) {
    if (!ctx) return;
    dbus_message_context *tmp;
    while ((tmp = ctx->parent)) {
        free(ctx);
        ctx = tmp;
    }
    free(ctx);
}

uint32_t
dbus_util_get_serial(dbus_method_call *call){
    if (!call) return -1;
    return call->serial;
}

void
dbus_util_set_reply_serial(dbus_method_call *call, uint32_t serial) {
    if (!call) return;
    if (call->reply){
        dbus_message_set_reply_serial(call->reply, serial);
        return;
    }
    if (call->msg){
        dbus_message_set_reply_serial(call->msg, serial);
    }
}


/*  Read functions      */

dbus_message_context *
dbus_util_make_read_context(dbus_method_call *call) {
    if (!call) return NULL;

    dbus_message_context *ctx = malloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->read = true;
    ctx->first_read = true;
    ctx->parent = NULL;
    ctx->container_type = -1;

    if (!dbus_message_iter_init(call->msg, &ctx->msg_iter)) {
        return NULL;
    }
    return ctx;
}

int
dbus_util_message_context_get_basic_ptr(dbus_message_context *ctx, int type, void *out) {
    if (!out || !ctx || !ctx->read) return DBUS_UTIL_INVALID_ARGUMENTS;
    if (!ctx->first_read && !dbus_message_iter_next(&ctx->msg_iter)) return DBUS_UTIL_DBUS_ERROR;
    if (dbus_message_iter_get_arg_type(&ctx->msg_iter) != type) return DBUS_UTIL_BAD_TYPE;
    ctx->first_read = false;
    dbus_message_iter_get_basic(&ctx->msg_iter, out);
    return DBUS_UTIL_SUCCESS;
}

int
dbus_util_message_context_get_bool(dbus_message_context *ctx, bool *out) {
    dbus_bool_t b;
    int ret = dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_BOOLEAN, &b);
    *out = (bool) b;

    return ret;
}

int
dbus_util_message_context_get_byte(dbus_message_context *ctx, int8_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_BYTE, val);
}

int
dbus_util_message_context_get_int16(dbus_message_context *ctx, int16_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_INT16, val);
}

int
dbus_util_message_context_get_uint16(dbus_message_context *ctx, uint16_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_UINT16, val);
}

int
dbus_util_message_context_get_int32(dbus_message_context *ctx, int32_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_INT32, val);
}

int
dbus_util_message_context_get_uint32(dbus_message_context *ctx, uint32_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_UINT32, val);
}

int
dbus_util_message_context_get_int64(dbus_message_context *ctx, int64_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_INT64, val);
}

int
dbus_util_message_context_get_uint64(dbus_message_context *ctx, uint64_t *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_UINT64, val);
}

int
dbus_util_message_context_get_double(dbus_message_context *ctx, double *val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_DOUBLE, val);
}

int
dbus_util_message_context_get_string(dbus_message_context *ctx, const char **val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_STRING, val);
}

int
dbus_util_message_context_get_object_path(dbus_message_context *ctx, const char **val) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_OBJECT_PATH, val);
}

int
dbus_util_message_context_get_fd(dbus_message_context *ctx, int *fd) {
    return dbus_util_message_context_get_basic_ptr(ctx, DBUS_TYPE_UNIX_FD, fd);
}


/*   Write functions   */

dbus_message_context *
dbus_util_make_reply_context(dbus_method_call *call) {
    if (!call) return NULL;

    dbus_message_context *context = malloc(sizeof(*context));
    if (!context) {
        perror("Error when calling mallloc");
        return NULL;
    }
    if (!call->reply) call->reply = dbus_message_new_method_return(call->msg);

    dbus_message_iter_init_append(call->reply, &context->msg_iter);
    context->parent = NULL;
    context->read = false;
    context->first_read = false;

    return context;
}

dbus_message_context *
dbus_util_make_write_context(dbus_method_call *call) {
    if (!call) return NULL;

    dbus_message_context *context = malloc(sizeof(*context));
    if (!context) {
        perror("Error when calling mallloc");
        return NULL;
    }

    dbus_message_iter_init_append(call->msg, &context->msg_iter);
    context->parent = NULL;
    context->read = false;
    context->first_read = false;

    return context;
}

dbus_method_call *
dbus_util_new_method_call(const char *destination, const char *path, const char *iface, const char *method) {
    if (!path || !iface || !method) return NULL;
    dbus_method_call *call = malloc(sizeof(*call));
    if (!call) {
        perror("Error when calling malloc");
        return NULL;
    }
    memset(call, 0, sizeof(*call));
    call->msg = dbus_message_new_method_call(destination, path, iface, method);
    if (!call->msg) {
        fprintf(stderr, "[dbus-util] DBus ran out of memory!\n");
        return NULL;
    }

    return call;
}

void
dbus_util_free_method_call(dbus_method_call *call) {
    if (!call) return;
    if (call->reply) dbus_message_unref(call->reply);
    if (call->msg) dbus_message_unref(call->msg);
    free(call);
}

int
dbus_util_send_method(dbus_bus *bus, dbus_method_call *call, dbus_util_method_reply_callback cb, void *param) {
    if (!bus || !bus->init || !call) return DBUS_UTIL_INVALID_ARGUMENTS;

    dbus_uint32_t *serial_ptr = &call->serial;
    if (cb) {
        struct dbus_method_return_cb_t *c = malloc(sizeof(*c));
        serial_ptr = &c->serial;
        c->cb = cb;
        c->param = param;
        vec_add(&bus->reply_vec, c);
    }

    if (!dbus_connection_send(bus->conn, call->msg, serial_ptr)) {
        fprintf(stderr, "[dbus-util] Failed sending message\n");
        return DBUS_UTIL_DBUS_ERROR;
    }
    dbus_message_unref(call->msg);
    call->msg = NULL;


    return DBUS_UTIL_SUCCESS;
}

void
dbus_util_message_context_add_basic_ptr(dbus_message_context *ctx, int type, const void *val) {
    if (!ctx || ctx->read) return;
    dbus_message_iter_append_basic(&ctx->msg_iter, type, val);
}

void
dbus_util_message_context_add_bool(dbus_message_context *ctx, bool val) {
    dbus_bool_t b = !!val;
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_BOOLEAN, &b);
}

void
dbus_util_message_context_add_byte(dbus_message_context *ctx, int8_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_BYTE, &val);
}

void
dbus_util_message_context_add_int16(dbus_message_context *ctx, int16_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_INT16, &val);
}

void
dbus_util_message_context_add_uint16(dbus_message_context *ctx, uint16_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_UINT16, &val);
}

void
dbus_util_message_context_add_int32(dbus_message_context *ctx, int32_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_INT32, &val);
}

void
dbus_util_message_context_add_uint32(dbus_message_context *ctx, uint32_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_UINT32, &val);
}

void
dbus_util_message_context_add_int64(dbus_message_context *ctx, int64_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_INT64, &val);
}

void
dbus_util_message_context_add_uint64(dbus_message_context *ctx, uint64_t val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_UINT64, &val);
}

void
dbus_util_message_context_add_double(dbus_message_context *ctx, double val) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_DOUBLE, &val);
}

void
dbus_util_message_context_add_string(dbus_message_context *ctx, const char *val) {
    if (!val) val = null_str;
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_STRING, &val);
}

void
dbus_util_message_context_add_object_path(dbus_message_context *ctx, const char *val) {
    if (!val) val = null_obj;
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_OBJECT_PATH, &val);
}

void
dbus_util_message_context_add_fd(dbus_message_context *ctx, int fd) {
    dbus_util_message_context_add_basic_ptr(ctx, DBUS_TYPE_UNIX_FD, &fd);
}

int
dbus_util_message_context_enter_array(dbus_message_context **ctx, const char *contained_sig) {
    return dbus_util_message_context_enter_container(ctx, contained_sig, DBUS_TYPE_ARRAY);
}

int
dbus_util_message_context_get_element_count(dbus_message_context *ctx) {
    if (!ctx || ctx->read || ctx->container_type != DBUS_TYPE_ARRAY) return 0;
    return dbus_message_iter_get_element_count(&ctx->msg_iter);
}

int
dbus_util_message_context_exit_array(dbus_message_context **ctx) {
    return dbus_util_message_context_exit_container(ctx, DBUS_TYPE_ARRAY);
}

int
dbus_util_message_context_enter_dict_entry(dbus_message_context **ctx) {
    return dbus_util_message_context_enter_container(ctx, NULL, DBUS_TYPE_DICT_ENTRY);
}

int
dbus_util_message_context_exit_dict_entry(dbus_message_context **ctx) {
    return dbus_util_message_context_exit_container(ctx, DBUS_TYPE_DICT_ENTRY);
}

int
dbus_util_message_context_enter_struct(dbus_message_context **ctx) {
    return dbus_util_message_context_enter_container(ctx, NULL, DBUS_TYPE_STRUCT);
}

int
dbus_util_message_context_exit_struct(dbus_message_context **ctx) {
    return dbus_util_message_context_exit_container(ctx, DBUS_TYPE_STRUCT);
}

int
dbus_util_message_context_enter_variant(dbus_message_context **ctx, const char *contained_sig) {
    return dbus_util_message_context_enter_container(ctx, contained_sig, DBUS_TYPE_VARIANT);
}

int
dbus_util_message_context_exit_variant(dbus_message_context **ctx) {
    return dbus_util_message_context_exit_container(ctx, DBUS_TYPE_VARIANT);
}

int
dbus_util_message_context_add_bool_variant(dbus_message_context *ctx, bool val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_BOOLEAN_AS_STRING))) return ret;
    dbus_util_message_context_add_bool(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_byte_variant(dbus_message_context *ctx, int8_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_BYTE_AS_STRING))) return ret;
    dbus_util_message_context_add_byte(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_int16_variant(dbus_message_context *ctx, int16_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_INT16_AS_STRING))) return ret;
    dbus_util_message_context_add_int16(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_uint16_variant(dbus_message_context *ctx, uint16_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_UINT16_AS_STRING))) return ret;
    dbus_util_message_context_add_uint16(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_int32_variant(dbus_message_context *ctx, int32_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_INT32_AS_STRING))) return ret;
    dbus_util_message_context_add_int32(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_uint32_variant(dbus_message_context *ctx, uint32_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_UINT32_AS_STRING))) return ret;
    dbus_util_message_context_add_uint32(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_int64_variant(dbus_message_context *ctx, int64_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_INT64_AS_STRING))) return ret;
    dbus_util_message_context_add_int64(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_uint64_variant(dbus_message_context *ctx, uint64_t val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_UINT64_AS_STRING))) return ret;
    dbus_util_message_context_add_uint64(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_double_variant(dbus_message_context *ctx, double val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_DOUBLE_AS_STRING))) return ret;
    dbus_util_message_context_add_double(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_string_variant(dbus_message_context *ctx, const char *val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_STRING_AS_STRING))) return ret;
    dbus_util_message_context_add_string(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}

int
dbus_util_message_context_add_object_path_variant(dbus_message_context *ctx, const char *val) {
    int ret;
    if ((ret = dbus_util_message_context_enter_variant(&ctx, DBUS_TYPE_OBJECT_PATH_AS_STRING))) return ret;
    dbus_util_message_context_add_object_path(ctx, val);
    return dbus_util_message_context_exit_variant(&ctx);
}



