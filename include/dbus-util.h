#ifndef DBUS_UTIL_DBUS_UTIL_H
#define DBUS_UTIL_DBUS_UTIL_H

#include <stdbool.h>
#include <stdint.h>

typedef struct dbus_bus_t dbus_bus;
struct dbus_bus_t;
typedef struct dbus_interface_t dbus_interface;
struct dbus_interface_t;
typedef struct dbus_method_call_t dbus_method_call;
struct dbus_method_call_t;
typedef struct dbus_message_context_t dbus_message_context;
struct dbus_message_context_t;
typedef struct dbus_object_t dbus_object;
struct dbus_object_t;

#ifndef DBUS_TYPES_H
typedef uint32_t dbus_bool_t;
#endif

enum dbus_util_error_code {
    DBUS_UTIL_SUCCESS = 0,
    DBUS_UTIL_ERR_MEM = -1,
    DBUS_UTIL_ASSERT_FAIL = -2,
    DBUS_UTIL_DBUS_ERROR = -3,
    DBUS_UTIL_ALREADY_EXISTS = -4,
    DBUS_UTIL_INVALID_ARGUMENTS = -5,
    DBUS_UTIL_INCORRECT_CLOSE = -6,
    DBUS_UTIL_BAD_TYPE = -7,
};

#ifndef DBUS_PROTOCOL_H
/* Taken from: https://dbus.freedesktop.org/doc/api/html/dbus-protocol_8h_source.html */
#define DBUS_TYPE_INVALID       ((int) '\0')
#define DBUS_TYPE_INVALID_AS_STRING        "\0"
#define DBUS_TYPE_BYTE          ((int) 'y')
#define DBUS_TYPE_BYTE_AS_STRING           "y"
#define DBUS_TYPE_BOOLEAN       ((int) 'b')
#define DBUS_TYPE_BOOLEAN_AS_STRING        "b"
#define DBUS_TYPE_INT16         ((int) 'n')
#define DBUS_TYPE_INT16_AS_STRING          "n"
#define DBUS_TYPE_UINT16        ((int) 'q')
#define DBUS_TYPE_UINT16_AS_STRING         "q"
#define DBUS_TYPE_INT32         ((int) 'i')
#define DBUS_TYPE_INT32_AS_STRING          "i"
#define DBUS_TYPE_UINT32        ((int) 'u')
#define DBUS_TYPE_UINT32_AS_STRING         "u"
#define DBUS_TYPE_INT64         ((int) 'x')
#define DBUS_TYPE_INT64_AS_STRING          "x"
#define DBUS_TYPE_UINT64        ((int) 't')
#define DBUS_TYPE_UINT64_AS_STRING         "t"
#define DBUS_TYPE_DOUBLE        ((int) 'd')
#define DBUS_TYPE_DOUBLE_AS_STRING         "d"
#define DBUS_TYPE_STRING        ((int) 's')
#define DBUS_TYPE_STRING_AS_STRING         "s"
#define DBUS_TYPE_OBJECT_PATH   ((int) 'o')
#define DBUS_TYPE_OBJECT_PATH_AS_STRING    "o"
#define DBUS_TYPE_SIGNATURE     ((int) 'g')
#define DBUS_TYPE_SIGNATURE_AS_STRING      "g"
#define DBUS_TYPE_UNIX_FD      ((int) 'h')
#define DBUS_TYPE_UNIX_FD_AS_STRING        "h"
#define DBUS_TYPE_ARRAY         ((int) 'a')
#define DBUS_TYPE_VARIANT       ((int) 'v')
#define DBUS_TYPE_VARIANT_AS_STRING        "v"
#define DBUS_TYPE_STRUCT        ((int) 'r')
#define DBUS_TYPE_STRUCT_AS_STRING         "r"
#define DBUS_TYPE_DICT_ENTRY    ((int) 'e')
#define DBUS_TYPE_DICT_ENTRY_AS_STRING     "e"
#endif

typedef void (*dbus_util_method_callback)(dbus_bus *bus, dbus_object *object, dbus_interface *interface, dbus_method_call *call,
                                          void *param);

typedef void (*dbus_util_property_get_callback)(dbus_bus *bus, dbus_message_context *ctx, void *param);
typedef void (*dbus_util_property_set_callback)(dbus_bus *bus, dbus_message_context *ctx, void *param);
typedef void (*dbus_util_method_reply_callback)(dbus_bus *bus, dbus_message_context *ctx, void *param);

/*      Initialization functions        */

int dbus_util_create_bus(dbus_bus **bus_out);

int dbus_util_create_bus_with_name(dbus_bus **bus_out, const char *name);

void dbus_util_free_bus(dbus_bus *bus);

dbus_object *dbus_util_find_object(const dbus_bus *bus, const char *name);

const char *dbus_util_get_error(dbus_bus *bus);

dbus_interface *dbus_util_find_interface(const dbus_object *object, const char *name);

int dbus_util_set_method_cb(dbus_interface *interface, const char *name, dbus_util_method_callback cb, void *param);

void dbus_util_poll_messages(dbus_bus *bus);

void dbus_util_emit_signals(dbus_bus *bus);



/*      Introspectable functions        */

int dbus_util_add_introspectable_interface(dbus_object *object);

int dbus_util_set_introspectable_xml(dbus_bus *bus, const char *xml_str);

int dbus_util_parse_introspection(dbus_bus *bus);


/*      Property functions              */

int dbus_util_add_property_interface(dbus_object *object);

int dbus_util_set_property_bool(dbus_interface *interface, const char *name, bool val);
int dbus_util_set_property_byte(dbus_interface *interface, const char *name, int8_t val);
int dbus_util_set_property_int16(dbus_interface *interface, const char *name, int16_t val);
int dbus_util_set_property_uint16(dbus_interface *interface, const char *name, uint16_t val);
int dbus_util_set_property_int32(dbus_interface *interface, const char *name, int32_t val);
int dbus_util_set_property_uint32(dbus_interface *interface, const char *name, uint32_t val);
int dbus_util_set_property_int64(dbus_interface *interface, const char *name, int64_t val);
int dbus_util_set_property_uint64(dbus_interface *interface, const char *name, uint64_t val);
int dbus_util_set_property_double(dbus_interface *interface, const char *name, double val);
int dbus_util_set_property_string(dbus_interface *interface, const char *name, const char *val);

bool dbus_util_get_property_bool(dbus_interface *interface, const char *name);
int8_t dbus_util_get_property_byte(dbus_interface *interface, const char *name);
int16_t dbus_util_get_property_int16(dbus_interface *interface, const char *name);
uint16_t dbus_util_get_property_uint16(dbus_interface *interface, const char *name);
int32_t dbus_util_get_property_int32(dbus_interface *interface, const char *name);
uint32_t dbus_util_get_property_uint32(dbus_interface *interface, const char *name);
int64_t dbus_util_get_property_int64(dbus_interface *interface, const char *name);
uint64_t dbus_util_get_property_uint64(dbus_interface *interface, const char *name);
double dbus_util_get_property_double(dbus_interface *interface, const char *name);
const char *dbus_util_get_property_string(dbus_interface *interface, const char *name);

#if __STDC_VERSION__ >= 201112L
#define dbus_util_set_property(interface,name,val) _Generic(val, \
                                                            bool: dbus_util_set_property_bool, \
                                                            int8_t: dbus_util_set_property_byte, \
                                                            int16_t: dbus_util_set_property_int16, \
                                                            uint16_t: dbus_util_set_property_uint16, \
                                                            int32_t: dbus_util_set_property_int32, \
                                                            uint32_t: dbus_util_set_property_uint32, \
                                                            int64_t: dbus_util_set_property_int64, \
                                                            uint64_t: dbus_util_set_property_uint64, \
                                                            double: dbus_util_set_property_double, \
                                                            float: dbus_util_set_property_double, \
                                                            char *: dbus_util_set_property_string \
                                                            )((interface),(name),(val))
#endif

int
dbus_util_set_property_ptr(dbus_interface *interface, const char *name, void *ptr);

int
dbus_util_set_property_cb(dbus_interface *interface, const char *name, dbus_util_property_get_callback get_cb,
                          dbus_util_property_set_callback set_cb, void *userp);

int dbus_util_invalidate_property(dbus_interface *interface, const char *name);


/*      Quick argument functions        */

int dbus_util_get_method_arguments(dbus_bus *bus, dbus_method_call *method_call, int first, ...);

int dbus_util_add_reply_values(dbus_bus *bus, dbus_method_call *method_call, int first, ...);

int dbus_util_send_empty_reply(dbus_method_call *method_call);

int dbus_util_send_error_reply(dbus_method_call *method_call, const char *error);

void dbus_util_message_context_free(dbus_message_context *ctx);


/*          Read functions              */

dbus_message_context *dbus_util_make_read_context(dbus_method_call *call);

int dbus_util_message_context_get_basic_ptr(dbus_message_context *ctx, int type, void *out);

int dbus_util_message_context_get_bool(dbus_message_context *ctx, bool *out);
int dbus_util_message_context_get_byte(dbus_message_context *ctx, int8_t *val);
int dbus_util_message_context_get_int16(dbus_message_context *ctx, int16_t *val);
int dbus_util_message_context_get_uint16(dbus_message_context *ctx, uint16_t *val);
int dbus_util_message_context_get_int32(dbus_message_context *ctx, int32_t *val);
int dbus_util_message_context_get_uint32(dbus_message_context *ctx, uint32_t *val);
int dbus_util_message_context_get_int64(dbus_message_context *ctx, int64_t *val);
int dbus_util_message_context_get_uint64(dbus_message_context *ctx, uint64_t *val);
int dbus_util_message_context_get_double(dbus_message_context *ctx, double *val);
int dbus_util_message_context_get_string(dbus_message_context *ctx, const char **val);
int dbus_util_message_context_get_object_path(dbus_message_context *ctx, const char **val);
int dbus_util_message_context_get_fd(dbus_message_context *ctx, int *fd);

/*          Write functions             */

dbus_message_context *dbus_util_make_reply_context(dbus_method_call *call);
dbus_message_context *dbus_util_make_write_context(dbus_method_call *call);

dbus_method_call *dbus_util_new_method_call(const char *destination, const char *path, const char *iface, const char *method);
void dbus_util_free_method_call(dbus_method_call *call);

int dbus_util_send_method(dbus_bus *bus, dbus_method_call *call, dbus_util_method_reply_callback cb, void *param);

void dbus_util_message_context_add_basic_ptr(dbus_message_context *ctx, int type, const void *val);

void dbus_util_message_context_add_bool(dbus_message_context *ctx, bool val);
void dbus_util_message_context_add_byte(dbus_message_context *ctx, int8_t val);
void dbus_util_message_context_add_int16(dbus_message_context *ctx, int16_t val);
void dbus_util_message_context_add_uint16(dbus_message_context *ctx, uint16_t val);
void dbus_util_message_context_add_int32(dbus_message_context *ctx, int32_t val);
void dbus_util_message_context_add_uint32(dbus_message_context *ctx, uint32_t val);
void dbus_util_message_context_add_int64(dbus_message_context *ctx, int64_t val);
void dbus_util_message_context_add_uint64(dbus_message_context *ctx, uint64_t val);
void dbus_util_message_context_add_double(dbus_message_context *ctx, double val);
void dbus_util_message_context_add_string(dbus_message_context *ctx, const char *val);
void dbus_util_message_context_add_object_path(dbus_message_context *ctx, const char *val);
void dbus_util_message_context_add_fd(dbus_message_context *ctx, int fd);

int dbus_util_message_context_enter_array(dbus_message_context **ctx, const char *contained_sig);
int dbus_util_message_context_get_element_count(dbus_message_context *ctx);
int dbus_util_message_context_exit_array(dbus_message_context **ctx);
int dbus_util_message_context_enter_dict_entry(dbus_message_context **ctx);
int dbus_util_message_context_exit_dict_entry(dbus_message_context **ctx);
int dbus_util_message_context_enter_struct(dbus_message_context **ctx);
int dbus_util_message_context_exit_struct(dbus_message_context **ctx);
int dbus_util_message_context_enter_variant(dbus_message_context **ctx, const char *contained_sig);
int dbus_util_message_context_exit_variant(dbus_message_context **ctx);

int dbus_util_message_context_add_bool_variant(dbus_message_context *ctx, bool val);
int dbus_util_message_context_add_byte_variant(dbus_message_context *ctx, int8_t val);
int dbus_util_message_context_add_int16_variant(dbus_message_context *ctx, int16_t val);
int dbus_util_message_context_add_uint16_variant(dbus_message_context *ctx, uint16_t val);
int dbus_util_message_context_add_int32_variant(dbus_message_context *ctx, int32_t val);
int dbus_util_message_context_add_uint32_variant(dbus_message_context *ctx, uint32_t val);
int dbus_util_message_context_add_int64_variant(dbus_message_context *ctx, int64_t val);
int dbus_util_message_context_add_uint64_variant(dbus_message_context *ctx, uint64_t val);
int dbus_util_message_context_add_double_variant(dbus_message_context *ctx, double val);
int dbus_util_message_context_add_string_variant(dbus_message_context *ctx, const char *val);
int dbus_util_message_context_add_object_path_variant(dbus_message_context *ctx, const char *val);

#endif //DBUS_UTIL_DBUS_UTIL_H
