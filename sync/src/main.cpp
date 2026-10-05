#include <gio/gio.h>
#include <glib-unix.h>
#include "protocol.hpp"
#include "link_security.hpp"
#include "dtls_tunnel.hpp"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

static const char* ADVERTISEMENT_PATH = "/org/sic/sink_advertisement";

static const char* SIC_DISCOVERY_UUID =
    "7e57a000-0000-4a4d-8f41-534943000001";

static const gchar introspection_xml[] =
    "<node>"
    "  <interface name='org.bluez.LEAdvertisement1'>"
    "    <method name='Release'/>"
    "    <property name='Type' type='s' access='read'/>"
    "    <property name='LocalName' type='s' access='read'/>"
    "    <property name='Discoverable' type='b' access='read'/>"
    "    <property name='ManufacturerData' type='a{sv}' access='read'/>"
    "  </interface>"
    "</node>";

static GMainLoop* main_loop = nullptr;
static GDBusConnection* connection = nullptr;
static GDBusProxy* advertising_manager = nullptr;

static bool advertisement_registered = false;
static bool shutting_down = false;
static const char* GATT_APP_PATH =
    "/org/sic/gatt";

static const char* GATT_SERVICE_PATH =
    "/org/sic/gatt/service0";

static const char* GATT_CHARACTERISTIC_PATH =
    "/org/sic/gatt/service0/char0";

static const char* SIC_LINK_SERVICE_UUID =
    "7e57a000-0000-4a4d-8f41-534943000010";

static const char* SIC_LINK_CHARACTERISTIC_UUID =
    "7e57a000-0000-4a4d-8f41-534943000011";

static GDBusProxy* gatt_manager = nullptr;

static bool gatt_registered = false;
static bool downlink_registered = false;
static bool notify_enabled = false;
static std::atomic<std::uint64_t> sink_sequence{1};
static std::string sink_nid;
static std::unique_ptr<sic::LinkSender> downlink_sender;
static std::unique_ptr<sic::LinkReceiver> downlink_receiver;
static std::mutex downlink_security_mutex;
static std::mutex dtls_mutex;
static sic::DatagramReassembler dtls_reassembler;
static std::atomic<bool> dtls_running{true};
static std::atomic<std::uint64_t> dtls_datagram_id{1};
static int dtls_socket = -1;
static std::string dtls_peer_nid;
static std::uint32_t dtls_peer_client = 0;
static void accept_dtls_uplink(const sic::Frame& frame);
static void dtls_sink_loop();

static sic::SessionKey load_key(const std::string& path) {
    sic::SessionKey key{};
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char*>(key.data()), key.size());
    if (input.gcount() != static_cast<std::streamsize>(key.size())) {
        throw std::runtime_error("chave de link invalida: " + path);
    }
    return key;
}



static GVariant* gatt_managed_objects() {

    GVariantBuilder objects;
    g_variant_builder_init(
        &objects,
        G_VARIANT_TYPE("a{oa{sa{sv}}}")
    );

    GVariantBuilder service_interfaces;
    g_variant_builder_init(
        &service_interfaces,
        G_VARIANT_TYPE("a{sa{sv}}")
    );

    GVariantBuilder service_properties;
    g_variant_builder_init(
        &service_properties,
        G_VARIANT_TYPE("a{sv}")
    );

    g_variant_builder_add(
        &service_properties,
        "{sv}",
        "UUID",
        g_variant_new_string(SIC_LINK_SERVICE_UUID)
    );

    g_variant_builder_add(
        &service_properties,
        "{sv}",
        "Primary",
        g_variant_new_boolean(TRUE)
    );

    g_variant_builder_add(
        &service_interfaces,
        "{sa{sv}}",
        "org.bluez.GattService1",
        &service_properties
    );

    g_variant_builder_add(
        &objects,
        "{oa{sa{sv}}}",
        GATT_SERVICE_PATH,
        &service_interfaces
    );

    GVariantBuilder char_interfaces;
    g_variant_builder_init(
        &char_interfaces,
        G_VARIANT_TYPE("a{sa{sv}}")
    );

    GVariantBuilder char_properties;
    g_variant_builder_init(
        &char_properties,
        G_VARIANT_TYPE("a{sv}")
    );

    g_variant_builder_add(
        &char_properties,
        "{sv}",
        "Service",
        g_variant_new_object_path(GATT_SERVICE_PATH)
    );

    g_variant_builder_add(
        &char_properties,
        "{sv}",
        "UUID",
        g_variant_new_string(SIC_LINK_CHARACTERISTIC_UUID)
    );

    GVariantBuilder flags;
    g_variant_builder_init(
        &flags,
        G_VARIANT_TYPE("as")
    );

    g_variant_builder_add(&flags, "s", "read");
    g_variant_builder_add(&flags, "s", "write");
    g_variant_builder_add(&flags, "s", "notify");

    g_variant_builder_add(
        &char_properties,
        "{sv}",
        "Flags",
        g_variant_builder_end(&flags)
    );

    g_variant_builder_add(
        &char_interfaces,
        "{sa{sv}}",
        "org.bluez.GattCharacteristic1",
        &char_properties
    );

    g_variant_builder_add(
        &objects,
        "{oa{sa{sv}}}",
        GATT_CHARACTERISTIC_PATH,
        &char_interfaces
    );

    return g_variant_builder_end(&objects);
}


static void object_manager_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant*,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "GetManagedObjects") == 0) {

        GVariant* objects = gatt_managed_objects();

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new(
                "(@a{oa{sa{sv}}})",
                objects
            )
        );

        return;
    }

    g_dbus_method_invocation_return_error(
        invocation,
        G_IO_ERROR,
        G_IO_ERROR_NOT_SUPPORTED,
        "Metodo ObjectManager nao suportado"
    );
}

static const GDBusInterfaceVTable object_manager_vtable = {
    object_manager_call,
    nullptr,
    nullptr,
    {0}
};


static GVariant* service_property(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* property_name,
    GError**,
    gpointer) {

    if (g_strcmp0(property_name, "UUID") == 0)
        return g_variant_new_string(SIC_LINK_SERVICE_UUID);

    if (g_strcmp0(property_name, "Primary") == 0)
        return g_variant_new_boolean(TRUE);

    return nullptr;
}

static const GDBusInterfaceVTable service_vtable = {
    nullptr,
    service_property,
    nullptr,
    {0}
};


static void send_downlink(const std::string& message);

static gboolean heartbeat_tick(gpointer) {
    sic::Frame heartbeat{"HEARTBEAT", sink_nid, "ALL", "CONTROL", 0, sink_sequence++, "alive"};
    send_downlink(sic::encode(heartbeat));
    return G_SOURCE_CONTINUE;
}

static void characteristic_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant* parameters,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "ReadValue") == 0) {

        const guint8 data[] = {
            0x53,
            0x49,
            0x4E,
            0x4B
        };

        GVariant* value =
            g_variant_new_fixed_array(
                G_VARIANT_TYPE_BYTE,
                data,
                sizeof(data),
                sizeof(guint8)
            );

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(@ay)", value)
        );

        return;
    }

    if (g_strcmp0(method_name, "WriteValue") == 0) {

        GVariant* bytes = nullptr;
        GVariant* options = nullptr;

        g_variant_get(
            parameters,
            "(@ay@a{sv})",
            &bytes,
            &options
        );

        gsize length = 0;

        const guint8* data =
            static_cast<const guint8*>(
                g_variant_get_fixed_array(
                    bytes,
                    &length,
                    sizeof(guint8)
                )
            );

        std::vector<std::uint8_t> protected_message(data, data + length);
        auto plaintext = downlink_receiver->verify(protected_message);
        if (!plaintext) {
            std::cerr << "SECURITY DROP: MAC invalido ou replay" << std::endl;
            g_variant_unref(bytes);
            g_variant_unref(options);
            g_dbus_method_invocation_return_value(invocation, nullptr);
            return;
        }
        std::string message(plaintext->begin(), plaintext->end());
        auto frame = sic::decode(message);
        if (frame && frame->service == "DTLS" && frame->destination == "SINK") {
            accept_dtls_uplink(*frame);
        } else if (frame && frame->type == "DATA" && frame->destination == "SINK") {
            std::cout << "INBOX SINK <- " << frame->source << ": " << frame->payload << std::endl;
            std::cout << "INBOX CLIENT=" << frame->client << std::endl;
            sic::Frame answer{"ACK", sink_nid, frame->source, frame->service, frame->client,
                              sink_sequence++, "Recebido: " + frame->payload};
            send_downlink(sic::encode(answer));
        } else {
            std::cout << "CONTROLO SINK: " << message << std::endl;
        }

        if (!downlink_registered &&
            length == 2 &&
            data[0] == 0x01 &&
            data[1] == 0x01) {

            downlink_registered = true;

            std::cout << std::endl;
            std::cout << "==============================" << std::endl;
            std::cout << "UPLINK DO NODE-A REGISTADO" << std::endl;
            std::cout << "DOWNLINK ATIVO: NODE-A" << std::endl;
            std::cout << "Downlinks ativos: 1" << std::endl;
            std::cout << "==============================" << std::endl;
        }

        g_variant_unref(bytes);
        g_variant_unref(options);

        g_dbus_method_invocation_return_value(
            invocation,
            nullptr
        );

        return;
    }

    if (g_strcmp0(method_name, "StartNotify") == 0) {

        notify_enabled = true;

        std::cout << std::endl;
        std::cout << "==============================" << std::endl;
        std::cout << "NOTIFY ATIVADO PELO NODE-A" << std::endl;
        std::cout << "DOWNLINK SINK -> NODE-A DISPONIVEL" << std::endl;
        std::cout << "==============================" << std::endl;

        sic::Frame hello{"HELLO", sink_nid, "ALL", "CONTROL", 0,
                         sink_sequence++, "Downlink ativo"};
        send_downlink(sic::encode(hello));

        g_dbus_method_invocation_return_value(
            invocation,
            nullptr
        );

        return;
    }

    if (g_strcmp0(method_name, "StopNotify") == 0) {

        notify_enabled = false;

        std::cout << std::endl;
        std::cout << "NOTIFY DESATIVADO PELO NODE-A" << std::endl;

        g_dbus_method_invocation_return_value(
            invocation,
            nullptr
        );

        return;
    }

    g_dbus_method_invocation_return_error(
        invocation,
        G_IO_ERROR,
        G_IO_ERROR_NOT_SUPPORTED,
        "Metodo GATT nao suportado"
    );
}


static GVariant* characteristic_property(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* property_name,
    GError**,
    gpointer) {

    if (g_strcmp0(property_name, "Service") == 0)
        return g_variant_new_object_path(GATT_SERVICE_PATH);

    if (g_strcmp0(property_name, "UUID") == 0)
        return g_variant_new_string(
            SIC_LINK_CHARACTERISTIC_UUID
        );

    if (g_strcmp0(property_name, "Flags") == 0) {

        GVariantBuilder flags;

        g_variant_builder_init(
            &flags,
            G_VARIANT_TYPE("as")
        );

        g_variant_builder_add(&flags, "s", "read");
        g_variant_builder_add(&flags, "s", "write");
        g_variant_builder_add(&flags, "s", "notify");

        return g_variant_builder_end(&flags);
    }

    return nullptr;
}


static void send_downlink(const std::string& message) {

    if (!notify_enabled) {
        std::cout
            << "DOWNLINK nao enviado: NODE-A ainda nao ativou Notify."
            << std::endl;
        return;
    }

    std::lock_guard<std::mutex> security_lock(downlink_security_mutex);
    auto protected_message = downlink_sender->protect(sic::bytes(message));
    GVariant* value =
        g_variant_new_fixed_array(
            G_VARIANT_TYPE_BYTE,
            protected_message.data(),
            protected_message.size(),
            sizeof(guint8)
        );

    GVariantBuilder changed;
    g_variant_builder_init(
        &changed,
        G_VARIANT_TYPE("a{sv}")
    );

    g_variant_builder_add(
        &changed,
        "{sv}",
        "Value",
        value
    );

    GVariantBuilder invalidated;
    g_variant_builder_init(
        &invalidated,
        G_VARIANT_TYPE("as")
    );

    g_dbus_connection_emit_signal(
        connection,
        nullptr,
        GATT_CHARACTERISTIC_PATH,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        g_variant_new(
            "(sa{sv}as)",
            "org.bluez.GattCharacteristic1",
            &changed,
            &invalidated
        ),
        nullptr
    );

    auto frame = sic::decode(message);
    if (frame && frame->service != "DTLS" && frame->type != "HEARTBEAT") {
        std::cout << "DOWNLINK SINK type=" << frame->type
                  << " destino=" << frame->destination << std::endl;
    }
}

static void accept_dtls_uplink(const sic::Frame& frame) {
    auto fragment = sic::decode_fragment(frame.payload);
    if (!fragment) {
        return;
    }
    std::lock_guard<std::mutex> lock(dtls_mutex);
    auto datagram = dtls_reassembler.accept(frame.source, *fragment);
    if (!datagram || dtls_socket < 0) {
        return;
    }
    dtls_peer_nid = frame.source;
    dtls_peer_client = frame.client;
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(4444);
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sendto(
        dtls_socket,
        datagram->data(),
        datagram->size(),
        0,
        reinterpret_cast<sockaddr*>(&server),
        sizeof(server)
    );
    std::cout << "DTLS SINK UPLINK DATAGRAM bytes=" << datagram->size() << std::endl;
}

static void dtls_sink_loop() {
    dtls_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dtls_socket < 0) {
        std::cerr << "DTLS SINK SOCKET FALHOU" << std::endl;
        return;
    }
    timeval timeout{1, 0};
    setsockopt(dtls_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(5556);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(dtls_socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        std::cerr << "DTLS SINK PORT 5556 INDISPONIVEL" << std::endl;
        close(dtls_socket);
        dtls_socket = -1;
        return;
    }
    std::cout << "DTLS SINK BRIDGE 127.0.0.1:5556 -> 127.0.0.1:4444" << std::endl;
    std::vector<char> buffer(65535);
    while (dtls_running) {
        auto received = recvfrom(dtls_socket, buffer.data(), buffer.size(), 0, nullptr, nullptr);
        if (received <= 0) {
            continue;
        }
        std::string destination;
        std::uint32_t client = 0;
        {
            std::lock_guard<std::mutex> lock(dtls_mutex);
            destination = dtls_peer_nid;
            client = dtls_peer_client;
        }
        if (destination.empty()) {
            continue;
        }
        std::string datagram(buffer.data(), static_cast<std::size_t>(received));
        auto id = dtls_datagram_id++;
        for (const auto& fragment : sic::fragment_datagram(id, datagram)) {
            sic::Frame frame{"DATA", sink_nid, destination, "DTLS", client,
                             sink_sequence++, sic::encode_fragment(fragment)};
            send_downlink(sic::encode(frame));
        }
        std::cout << "DTLS SINK DOWNLINK DATAGRAM bytes=" << received << std::endl;
    }
    close(dtls_socket);
    dtls_socket = -1;
}

static const GDBusInterfaceVTable characteristic_vtable = {
    characteristic_call,
    characteristic_property,
    nullptr,
    {0}
};


static void on_gatt_registered(
    GObject* source,
    GAsyncResult* result,
    gpointer) {

    GError* error = nullptr;

    GVariant* reply =
        g_dbus_proxy_call_finish(
            G_DBUS_PROXY(source),
            result,
            &error
        );

    if (!reply) {

        std::cerr
            << "Erro ao registar GATT: "
            << error->message
            << std::endl;

        g_error_free(error);
        g_main_loop_quit(main_loop);
        return;
    }

    g_variant_unref(reply);

    gatt_registered = true;

    std::cout
        << "GATT do SINK ativo!"
        << std::endl;

    std::cout
        << "A aguardar uplink do NODE-A..."
        << std::endl;
}

static void handle_method_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant*,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "Release") == 0) {
        advertisement_registered = false;

        g_dbus_method_invocation_return_value(
            invocation,
            nullptr
        );

        if (!shutting_down && main_loop != nullptr) {
            g_main_loop_quit(main_loop);
        }
    }
}

static GVariant* handle_get_property(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* property_name,
    GError**,
    gpointer) {

    if (g_strcmp0(property_name, "Type") == 0) {
        return g_variant_new_string("peripheral");
    }

    if (g_strcmp0(property_name, "LocalName") == 0) {
        return g_variant_new_string("SIC-SINK");
    }

    if (g_strcmp0(property_name, "Discoverable") == 0) {
        return g_variant_new_boolean(TRUE);
    }

    if (g_strcmp0(property_name, "ManufacturerData") == 0) {


        const guint8 discovery_data[] = {
            0x01,
            0x01,
            0xFF
        };

        GVariantBuilder builder;

        g_variant_builder_init(
            &builder,
            G_VARIANT_TYPE("a{sv}")
        );

        GVariant* byte_array =
            g_variant_new_fixed_array(
                G_VARIANT_TYPE_BYTE,
                discovery_data,
                sizeof(discovery_data),
                sizeof(guint8)
            );

        g_variant_builder_add(
            &builder,
            "{sv}",
            SIC_DISCOVERY_UUID,
            byte_array
        );

        return g_variant_builder_end(&builder);
    }

    return nullptr;
}

static const GDBusInterfaceVTable interface_vtable = {
    handle_method_call,
    handle_get_property,
    nullptr,
    {0}
};

static void on_unregister_finished(
    GObject* source_object,
    GAsyncResult* result,
    gpointer) {

    GError* error = nullptr;

    GVariant* reply = g_dbus_proxy_call_finish(
        G_DBUS_PROXY(source_object),
        result,
        &error
    );

    if (reply != nullptr) {
        g_variant_unref(reply);
        std::cout
            << "Advertising do Sink terminado."
            << std::endl;
    } else {
        std::cerr
            << "Aviso ao terminar advertising: "
            << error->message
            << std::endl;

        g_error_free(error);
    }

    advertisement_registered = false;

    if (main_loop != nullptr) {
        g_main_loop_quit(main_loop);
    }
}

static gboolean handle_signal(gpointer) {

    if (shutting_down) {
        return G_SOURCE_REMOVE;
    }

    shutting_down = true;

    std::cout
        << "\nA terminar advertising..."
        << std::endl;

    if (!advertisement_registered) {
        g_main_loop_quit(main_loop);
        return G_SOURCE_REMOVE;
    }

    g_dbus_proxy_call(
        advertising_manager,
        "UnregisterAdvertisement",
        g_variant_new(
            "(o)",
            ADVERTISEMENT_PATH
        ),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        nullptr,
        on_unregister_finished,
        nullptr
    );

    return G_SOURCE_REMOVE;
}

static void on_register_finished(
    GObject* source_object,
    GAsyncResult* result,
    gpointer) {

    GError* error = nullptr;

    GVariant* reply = g_dbus_proxy_call_finish(
        G_DBUS_PROXY(source_object),
        result,
        &error
    );

    if (reply == nullptr) {
        std::cerr
            << "Erro ao iniciar advertising: "
            << error->message
            << std::endl;

        g_error_free(error);
        g_main_loop_quit(main_loop);
        return;
    }

    g_variant_unref(reply);

    advertisement_registered = true;

    std::cout << "Advertising do SINK ativo!" << std::endl;
    std::cout << "Nome: SIC-SINK" << std::endl;
    std::cout << "SIC Discovery: 01 01 FF" << std::endl;
    std::cout << "Ctrl+C para terminar." << std::endl;
}

int main() {

    GError* error = nullptr;

    try {
        const char* home = std::getenv("HOME");
        std::string config = std::string(home ? home : "") + "/.config/sic/";
        std::ifstream nid_input(config + "nid");
        std::getline(nid_input, sink_nid);
        if (sink_nid.empty()) {
            throw std::runtime_error("NID do SINK inexistente");
        }
        auto key = load_key(config + "links/downlink.key");
        downlink_sender = std::make_unique<sic::LinkSender>(key);
        downlink_receiver = std::make_unique<sic::LinkReceiver>(key);
    } catch (const std::exception& e) {
        std::cerr << "SEGURANCA NAO INICIALIZADA: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    std::cout
        << "A iniciar advertising do SIC-SINK..."
        << std::endl;

    main_loop = g_main_loop_new(nullptr, FALSE);
    g_timeout_add_seconds(5, heartbeat_tick, nullptr);

    connection = g_bus_get_sync(
        G_BUS_TYPE_SYSTEM,
        nullptr,
        &error
    );

    if (connection == nullptr) {
        std::cerr
            << "Erro ao ligar ao D-Bus: "
            << error->message
            << std::endl;

        g_error_free(error);
        return EXIT_FAILURE;
    }

    GDBusNodeInfo* introspection_data =
        g_dbus_node_info_new_for_xml(
            introspection_xml,
            &error
        );

    if (introspection_data == nullptr) {
        std::cerr
            << "Erro na descricao D-Bus: "
            << error->message
            << std::endl;

        g_error_free(error);
        return EXIT_FAILURE;
    }



    const gchar* app_xml =
        "<node>"
        "<interface name='org.freedesktop.DBus.ObjectManager'>"
        "<method name='GetManagedObjects'>"
        "<arg name='objects' type='a{oa{sa{sv}}}' direction='out'/>"
        "</method>"
        "</interface>"
        "</node>";

    GDBusNodeInfo* app_info =
        g_dbus_node_info_new_for_xml(
            app_xml,
            &error
        );

    guint object_manager_id =
        g_dbus_connection_register_object(
            connection,
            GATT_APP_PATH,
            app_info->interfaces[0],
            &object_manager_vtable,
            nullptr,
            nullptr,
            &error
        );

    const gchar* service_xml =
        "<node>"
        "<interface name='org.bluez.GattService1'>"
        "<property name='UUID' type='s' access='read'/>"
        "<property name='Primary' type='b' access='read'/>"
        "</interface>"
        "</node>";

    GDBusNodeInfo* service_info =
        g_dbus_node_info_new_for_xml(
            service_xml,
            &error
        );

    guint service_id =
        g_dbus_connection_register_object(
            connection,
            GATT_SERVICE_PATH,
            service_info->interfaces[0],
            &service_vtable,
            nullptr,
            nullptr,
            &error
        );

    const gchar* characteristic_xml =
        "<node>"
        "<interface name='org.bluez.GattCharacteristic1'>"
        "<method name='ReadValue'>"
        "<arg name='options' type='a{sv}' direction='in'/>"
        "<arg name='value' type='ay' direction='out'/>"
        "</method>"
        "<method name='WriteValue'>"
        "<arg name='value' type='ay' direction='in'/>"
        "<arg name='options' type='a{sv}' direction='in'/>"
        "</method>"
        "<method name='StartNotify'/>"
        "<method name='StopNotify'/>"
        "<property name='Service' type='o' access='read'/>"
        "<property name='UUID' type='s' access='read'/>"
        "<property name='Flags' type='as' access='read'/>"
        "<property name='Value' type='ay' access='read'/>"
        "</interface>"
        "</node>";

    GDBusNodeInfo* characteristic_info =
        g_dbus_node_info_new_for_xml(
            characteristic_xml,
            &error
        );

    guint characteristic_id =
        g_dbus_connection_register_object(
            connection,
            GATT_CHARACTERISTIC_PATH,
            characteristic_info->interfaces[0],
            &characteristic_vtable,
            nullptr,
            nullptr,
            &error
        );

    gatt_manager =
        g_dbus_proxy_new_sync(
            connection,
            G_DBUS_PROXY_FLAGS_NONE,
            nullptr,
            "org.bluez",
            "/org/bluez/hci0",
            "org.bluez.GattManager1",
            nullptr,
            &error
        );

    if (gatt_manager == nullptr) {

        std::cerr
            << "Erro ao obter GattManager1: "
            << error->message
            << std::endl;

        g_error_free(error);
        return EXIT_FAILURE;
    }

    GVariantBuilder gatt_options;

    g_variant_builder_init(
        &gatt_options,
        G_VARIANT_TYPE("a{sv}")
    );

    g_dbus_proxy_call(
        gatt_manager,
        "RegisterApplication",
        g_variant_new(
            "(oa{sv})",
            GATT_APP_PATH,
            &gatt_options
        ),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        nullptr,
        on_gatt_registered,
        nullptr
    );

    guint registration_id =
        g_dbus_connection_register_object(
            connection,
            ADVERTISEMENT_PATH,
            introspection_data->interfaces[0],
            &interface_vtable,
            nullptr,
            nullptr,
            &error
        );

    if (registration_id == 0) {
        std::cerr
            << "Erro ao registar objeto D-Bus: "
            << error->message
            << std::endl;

        g_error_free(error);
        return EXIT_FAILURE;
    }

    advertising_manager = g_dbus_proxy_new_sync(
        connection,
        G_DBUS_PROXY_FLAGS_NONE,
        nullptr,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.LEAdvertisingManager1",
        nullptr,
        &error
    );

    if (advertising_manager == nullptr) {
        std::cerr
            << "Erro ao obter advertising manager: "
            << error->message
            << std::endl;

        g_error_free(error);
        return EXIT_FAILURE;
    }

    GVariantBuilder options_builder;

    g_variant_builder_init(
        &options_builder,
        G_VARIANT_TYPE("a{sv}")
    );

    g_dbus_proxy_call(
        advertising_manager,
        "RegisterAdvertisement",
        g_variant_new(
            "(oa{sv})",
            ADVERTISEMENT_PATH,
            &options_builder
        ),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        nullptr,
        on_register_finished,
        nullptr
    );

    g_unix_signal_add(
        SIGINT,
        handle_signal,
        nullptr
    );

    g_unix_signal_add(
        SIGTERM,
        handle_signal,
        nullptr
    );

    dtls_running = true;
    std::thread dtls_thread(dtls_sink_loop);
    g_main_loop_run(main_loop);
    dtls_running = false;
    dtls_thread.join();

    g_object_unref(advertising_manager);
    if (gatt_manager != nullptr)
        g_object_unref(gatt_manager);

    g_dbus_connection_unregister_object(
        connection,
        characteristic_id
    );

    g_dbus_connection_unregister_object(
        connection,
        service_id
    );

    g_dbus_connection_unregister_object(
        connection,
        object_manager_id
    );

    g_dbus_node_info_unref(characteristic_info);
    g_dbus_node_info_unref(service_info);
    g_dbus_node_info_unref(app_info);



    g_dbus_connection_unregister_object(
        connection,
        registration_id
    );

    g_dbus_node_info_unref(introspection_data);
    g_object_unref(connection);
    g_main_loop_unref(main_loop);

    return EXIT_SUCCESS;
}
