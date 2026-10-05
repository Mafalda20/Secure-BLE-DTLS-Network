#include <gio/gio.h>
#include <glib-unix.h>
#include <simpleble/SimpleBLE.h>
#include "protocol.hpp"
#include "link_security.hpp"
#include "dtls_tunnel.hpp"

#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <set>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

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

static const char* ADVERTISEMENT_PATH =
    "/org/sic/advertisement";

static GMainLoop* gatt_loop = nullptr;
static GDBusConnection* gatt_connection = nullptr;
static GDBusProxy* gatt_manager = nullptr;

static bool gatt_registered = false;
static bool notify_enabled = false;
static std::atomic<bool> advertising_active{false};
static std::string node_name = "SIC-NODE";
static std::string node_nid;
static std::uint32_t inbox_client = 1;
static int node_hop = 0;
static int configured_hop = 0;
static bool root_child = false;
static std::string uplink_nid;
static std::string uplink_name;
static std::atomic<std::uint64_t> node_sequence{1};
static std::atomic<std::uint64_t> forwarded_uplink{0};
static std::atomic<std::uint64_t> forwarded_downlink{0};
static std::atomic<std::uint64_t> missed_heartbeats{0};
static std::atomic<std::int64_t> last_heartbeat_ms{0};
static std::atomic<bool> router_running{true};
static SimpleBLE::Peripheral uplink;
static std::string recovery_parent_name;
static std::mutex uplink_mutex;
static bool uplink_ready = false;
static void emit_downlink(const std::string& message);
static sic::SessionKey uplink_key{};
static std::unique_ptr<sic::LinkSender> uplink_sender;
static std::unique_ptr<sic::LinkReceiver> uplink_receiver;
static std::unique_ptr<sic::LinkSender> child_sender;
static std::unique_ptr<sic::LinkReceiver> child_receiver;
static std::mutex topology_mutex;
static std::set<std::string> downlinks;
static std::unordered_map<std::string, std::string> forwarding_table;
static std::string child_device_path;
static int dtls_socket = -1;
static sockaddr_in dtls_client_address{};
static socklen_t dtls_client_address_size = sizeof(dtls_client_address);
static bool dtls_client_known = false;
static std::mutex dtls_mutex;
static sic::DatagramReassembler dtls_reassembler;
static std::atomic<std::uint64_t> dtls_datagram_id{1};
static void deliver_dtls_downlink(const sic::Frame& frame);
static void dtls_bridge_loop();
static void stop_stale_discovery();
static void forget_device(const std::string& address);
static void pause_downlink();
static void resume_downlink();

static sic::SessionKey load_session_key(const std::string& path) {
    sic::SessionKey key{};
    std::ifstream input(path, std::ios::binary);
    input.read(reinterpret_cast<char*>(key.data()), key.size());
    if (input.gcount() != static_cast<std::streamsize>(key.size())) {
        throw std::runtime_error("chave de link invalida: " + path);
    }
    return key;
}

static std::int64_t monotonic_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

static void handle_downlink(SimpleBLE::ByteArray data) {
    auto plaintext = uplink_receiver->verify(data);
    if (!plaintext) {
        std::cerr << "SECURITY DROP UPLINK: MAC invalido ou replay" << std::endl;
        return;
    }
    std::string message(plaintext->begin(), plaintext->end());
    auto frame = sic::decode(message);
    if (!frame) {
        std::cout << "DOWNLINK INVALIDO" << std::endl;
        return;
    }
    if (frame->service == "DTLS" && frame->destination == node_nid) {
        deliver_dtls_downlink(*frame);
        return;
    }
    if (frame->type == "HEARTBEAT" || frame->type == "HELLO") {
        last_heartbeat_ms = monotonic_ms();
        missed_heartbeats = 0;
        node_hop = configured_hop;
        uplink_nid = frame->source;
        std::cout << "HEARTBEAT OK " << node_name << std::endl;
    }
    if ((frame->destination == node_nid || frame->destination == "ALL") &&
        frame->service != "CONTROL") {
        std::cout << "INBOX " << node_name << " <- " << frame->source
                  << ": " << frame->payload << std::endl;
    }
    if (frame->destination != node_nid) {
        if (frame->type == "HEARTBEAT" || frame->type == "HELLO") {
            auto rebroadcast = *frame;
            rebroadcast.source = node_nid;
            message = sic::encode(rebroadcast);
        }
        emit_downlink(message);
    }
}

static bool reconnect_uplink() {
    std::string stale_address;
    {
        std::lock_guard<std::mutex> lock(uplink_mutex);
        uplink_ready = false;
        try {
            stale_address = uplink.address();
            if (uplink.is_connected()) {
                uplink.disconnect();
            }
        } catch (...) {
        }
    }
    try {
        pause_downlink();
        stop_stale_discovery();
        if (!stale_address.empty()) {
            forget_device(stale_address);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto adapters = SimpleBLE::Adapter::get_adapters();
        if (adapters.empty()) {
            std::cerr << "RECONEXAO PENDENTE: adaptador BLE indisponivel" << std::endl;
            return false;
        }
        auto recovery_adapter = adapters.front();
        recovery_adapter.scan_for(8000);
        SimpleBLE::Peripheral refreshed;
        bool found = false;
        for (auto& device : recovery_adapter.scan_get_results()) {
            if (!device.is_connectable()) {
                continue;
            }
            if (!recovery_parent_name.empty() &&
                device.identifier().find(recovery_parent_name) == std::string::npos) {
                continue;
            }
            for (const auto& entry : device.manufacturer_data()) {
                const auto& data = entry.second;
                if (data.size() >= 3 && data[0] == 1 &&
                    (data[1] == 1 || (data[1] == 2 && data[2] != 0xFF))) {
                    refreshed = device;
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            std::cerr << "RECONEXAO PENDENTE: parent ainda nao visivel" << std::endl;
            return false;
        }
        refreshed.connect();
        if (!refreshed.is_connected()) {
            return false;
        }
        uplink_receiver = std::make_unique<sic::LinkReceiver>(uplink_key);
        refreshed.notify(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, handle_downlink);
        sic::Frame registration{"REGISTER", node_nid, "SINK", "CONTROL", 0,
                                node_sequence++, node_name};
        auto protected_registration = uplink_sender->protect(sic::bytes(sic::encode(registration)));
        refreshed.write_request(
            SIC_LINK_SERVICE_UUID,
            SIC_LINK_CHARACTERISTIC_UUID,
            protected_registration
        );
        {
            std::lock_guard<std::mutex> lock(uplink_mutex);
            uplink = refreshed;
            uplink_ready = true;
        }
        resume_downlink();
        std::cout << "UPLINK RECUPERADO" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "RECONEXAO PENDENTE: " << e.what() << std::endl;
        return false;
    }
}

static void emit_downlink(const std::string& message) {
    if (!notify_enabled || !gatt_connection || !child_sender) {
        return;
    }
    auto protected_message = child_sender->protect(sic::bytes(message));
    GVariant* value = g_variant_new_fixed_array(
        G_VARIANT_TYPE_BYTE,
        protected_message.data(),
        protected_message.size(),
        sizeof(guint8)
    );
    GVariantBuilder changed;
    g_variant_builder_init(&changed, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&changed, "{sv}", "Value", value);
    GVariantBuilder invalidated;
    g_variant_builder_init(&invalidated, G_VARIANT_TYPE("as"));
    g_dbus_connection_emit_signal(
        gatt_connection,
        nullptr,
        GATT_CHARACTERISTIC_PATH,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        g_variant_new("(sa{sv}as)", "org.bluez.GattCharacteristic1", &changed, &invalidated),
        nullptr
    );
    auto frame = sic::decode(message);
    if (frame && frame->service != "DTLS" && frame->type != "HEARTBEAT") {
        std::cout << "DOWNLINK FORWARD type=" << frame->type
                  << " destino=" << frame->destination << std::endl;
    }
    ++forwarded_downlink;
}

static bool send_uplink(const std::string& message) {
    std::lock_guard<std::mutex> lock(uplink_mutex);
    if (!uplink_ready || !uplink.is_connected()) {
        return false;
    }
    auto protected_message = uplink_sender->protect(sic::bytes(message));
    uplink.write_request(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, protected_message);
    auto frame = sic::decode(message);
    if (frame && frame->service != "DTLS") {
        std::cout << "UPLINK FORWARD type=" << frame->type
                  << " origem=" << frame->source << std::endl;
    }
    ++forwarded_uplink;
    return true;
}

static void deliver_dtls_downlink(const sic::Frame& frame) {
    auto fragment = sic::decode_fragment(frame.payload);
    if (!fragment) {
        return;
    }
    std::lock_guard<std::mutex> lock(dtls_mutex);
    auto datagram = dtls_reassembler.accept(frame.source, *fragment);
    if (!datagram || !dtls_client_known || dtls_socket < 0) {
        return;
    }
    sendto(
        dtls_socket,
        datagram->data(),
        datagram->size(),
        0,
        reinterpret_cast<sockaddr*>(&dtls_client_address),
        dtls_client_address_size
    );
    std::cout << "DTLS DOWNLINK DATAGRAM bytes=" << datagram->size() << std::endl;
}

static void dtls_bridge_loop() {
    dtls_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dtls_socket < 0) {
        std::cerr << "DTLS BRIDGE SOCKET FALHOU" << std::endl;
        return;
    }
    timeval timeout{1, 0};
    setsockopt(dtls_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(5555);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(dtls_socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        std::cerr << "DTLS BRIDGE PORT 5555 INDISPONIVEL" << std::endl;
        close(dtls_socket);
        dtls_socket = -1;
        return;
    }
    std::cout << "DTLS BRIDGE 127.0.0.1:5555 ATIVO" << std::endl;
    std::vector<char> buffer(65535);
    while (router_running) {
        sockaddr_in peer{};
        socklen_t peer_size = sizeof(peer);
        auto received = recvfrom(
            dtls_socket,
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<sockaddr*>(&peer),
            &peer_size
        );
        if (received <= 0) {
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(dtls_mutex);
            dtls_client_address = peer;
            dtls_client_address_size = peer_size;
            dtls_client_known = true;
        }
        std::string datagram(buffer.data(), static_cast<std::size_t>(received));
        auto id = dtls_datagram_id++;
        for (const auto& fragment : sic::fragment_datagram(id, datagram)) {
            sic::Frame frame{"DATA", node_nid, "SINK", "DTLS", inbox_client,
                             node_sequence++, sic::encode_fragment(fragment)};
            send_uplink(sic::encode(frame));
        }
        std::cout << "DTLS UPLINK DATAGRAM bytes=" << received << std::endl;
    }
    close(dtls_socket);
    dtls_socket = -1;
}

static void advertisement_method_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant*,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "Release") == 0) {

        advertising_active = false;

        std::cout
            << "Advertising de " << node_name << " libertado."
            << std::endl;

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
        "Metodo advertising nao suportado"
    );
}

static GVariant* advertisement_get_property(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* property_name,
    GError**,
    gpointer) {

    if (g_strcmp0(property_name, "Type") == 0)
        return g_variant_new_string("peripheral");

    if (g_strcmp0(property_name, "LocalName") == 0)
        return g_variant_new_string(node_name.c_str());

    if (g_strcmp0(property_name, "Discoverable") == 0)
        return g_variant_new_boolean(TRUE);

    if (g_strcmp0(property_name, "ManufacturerData") == 0) {

        const guint8 data[] = {0x01, 0x02, static_cast<guint8>(node_hop)};

        GVariantBuilder builder;

        g_variant_builder_init(
            &builder,
            G_VARIANT_TYPE("a{qv}")
        );

        GVariant* bytes =
            g_variant_new_fixed_array(
                G_VARIANT_TYPE_BYTE,
                data,
                sizeof(data),
                sizeof(guint8)
            );

        g_variant_builder_add(
            &builder,
            "{qv}",
            0xFFFF,
            bytes
        );

        return g_variant_builder_end(&builder);
    }

    return nullptr;
}

static const GDBusInterfaceVTable advertisement_vtable = {
    advertisement_method_call,
    advertisement_get_property,
    nullptr,
    {0}
};

static void on_advertisement_registered(
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

        advertising_active = false;

        std::cerr
            << "Erro ao registar advertising de " << node_name << ": "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    g_variant_unref(reply);

    advertising_active = true;

    std::cout
        << "ADVERTISING DE " << node_name << " ATIVO!"
        << std::endl;

    std::cout
        << "Nome: " << node_name
        << std::endl;

    std::cout
        << "SIC Discovery: 01 02 " << node_hop
        << std::endl;
}

static GVariant* get_managed_objects() {

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

    GVariantBuilder characteristic_interfaces;
    g_variant_builder_init(
        &characteristic_interfaces,
        G_VARIANT_TYPE("a{sa{sv}}")
    );

    GVariantBuilder characteristic_properties;
    g_variant_builder_init(
        &characteristic_properties,
        G_VARIANT_TYPE("a{sv}")
    );

    g_variant_builder_add(
        &characteristic_properties,
        "{sv}",
        "Service",
        g_variant_new_object_path(GATT_SERVICE_PATH)
    );

    g_variant_builder_add(
        &characteristic_properties,
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
        &characteristic_properties,
        "{sv}",
        "Flags",
        g_variant_builder_end(&flags)
    );

    g_variant_builder_add(
        &characteristic_interfaces,
        "{sa{sv}}",
        "org.bluez.GattCharacteristic1",
        &characteristic_properties
    );

    g_variant_builder_add(
        &objects,
        "{oa{sa{sv}}}",
        GATT_CHARACTERISTIC_PATH,
        &characteristic_interfaces
    );

    return g_variant_builder_end(&objects);
}

static void object_manager_method_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant*,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "GetManagedObjects") == 0) {

        GVariant* objects = get_managed_objects();

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
        "Metodo nao suportado"
    );
}

static const GDBusInterfaceVTable object_manager_vtable = {
    object_manager_method_call,
    nullptr,
    nullptr,
    {0}
};

static GVariant* service_get_property(
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
    service_get_property,
    nullptr,
    {0}
};

static void characteristic_method_call(
    GDBusConnection*,
    const gchar*,
    const gchar*,
    const gchar*,
    const gchar* method_name,
    GVariant* parameters,
    GDBusMethodInvocation* invocation,
    gpointer) {

    if (g_strcmp0(method_name, "ReadValue") == 0) {

        const guint8 data[] = {0x42};

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

        std::cout << std::endl;
        std::cout
            << "=============================="
            << std::endl;

        GVariant* bytes = nullptr;
        GVariant* options = nullptr;

        g_variant_get(
            parameters,
            "(@ay@a{sv})",
            &bytes,
            &options
        );

        GVariant* device_option = g_variant_lookup_value(
            options,
            "device",
            G_VARIANT_TYPE_OBJECT_PATH
        );
        if (device_option) {
            std::lock_guard<std::mutex> lock(topology_mutex);
            child_device_path = g_variant_get_string(device_option, nullptr);
            g_variant_unref(device_option);
        }

        gsize length = 0;

        const guint8* data =
            static_cast<const guint8*>(
                g_variant_get_fixed_array(
                    bytes,
                    &length,
                    sizeof(guint8)
                )
            );

        if (!child_receiver) {
            std::cerr << "SECURITY DROP CHILD: chave inexistente" << std::endl;
            g_variant_unref(bytes);
            g_variant_unref(options);
            g_dbus_method_invocation_return_value(invocation, nullptr);
            return;
        }
        std::vector<std::uint8_t> protected_message(data, data + length);
        auto plaintext = child_receiver->verify(protected_message);
        if (!plaintext) {
            std::cerr << "SECURITY DROP CHILD: MAC invalido ou replay" << std::endl;
            g_variant_unref(bytes);
            g_variant_unref(options);
            g_dbus_method_invocation_return_value(invocation, nullptr);
            return;
        }
        std::string message(plaintext->begin(), plaintext->end());
        auto frame = sic::decode(message);
        if (frame) {
            {
                std::lock_guard<std::mutex> lock(topology_mutex);
                downlinks.insert(frame->source);
                forwarding_table[frame->source] = "downlink";
            }
            std::cout << "CHILD " << frame->source << " -> " << node_nid << std::endl;
            try {
                if (!send_uplink(message)) {
                    std::cerr << "UPLINK INDISPONIVEL" << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "ERRO FORWARD UPLINK: " << e.what() << std::endl;
            }
        } else {
            std::cout << "CONTROLO CHILD: " << message << std::endl;
        }

        std::cout
            << "=============================="
            << std::endl;

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

        g_dbus_method_invocation_return_value(
            invocation,
            nullptr
        );

        return;
    }

    if (g_strcmp0(method_name, "StopNotify") == 0) {

        notify_enabled = false;

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

static GVariant* characteristic_get_property(
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

static const GDBusInterfaceVTable characteristic_vtable = {
    characteristic_method_call,
    characteristic_get_property,
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
            << "Erro ao registar GATT em " << node_name << ": "
            << error->message
            << std::endl;

        g_error_free(error);

        return;
    }

    g_variant_unref(reply);

    gatt_registered = true;

    std::cout
        << "GATT DE " << node_name << " ATIVO!"
        << std::endl;

    std::cout
        << "Characteristic de DOWNLINK pronta."
        << std::endl;
}

static void start_gatt_server() {

    GError* error = nullptr;

    gatt_loop =
        g_main_loop_new(nullptr, FALSE);

    gatt_connection =
        g_bus_get_sync(
            G_BUS_TYPE_SYSTEM,
            nullptr,
            &error
        );

    if (!gatt_connection) {

        std::cerr
            << "Erro D-Bus GATT: "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    GDBusNodeInfo* advertisement_info =
        g_dbus_node_info_new_for_xml(
            "<node>"
            "<interface name='org.bluez.LEAdvertisement1'>"
            "<method name='Release'/>"
            "<property name='Type' type='s' access='read'/>"
            "<property name='LocalName' type='s' access='read'/>"
            "<property name='Discoverable' type='b' access='read'/>"
            "<property name='ManufacturerData' type='a{qv}' access='read'/>"
            "</interface>"
            "</node>",
            &error
        );

    if (!advertisement_info) {

        std::cerr
            << "Erro XML Advertising: "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    g_dbus_connection_register_object(
        gatt_connection,
        ADVERTISEMENT_PATH,
        advertisement_info->interfaces[0],
        &advertisement_vtable,
        nullptr,
        nullptr,
        &error
    );

    if (error) {

        std::cerr
            << "Erro ao registar objeto Advertising: "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    GDBusNodeInfo* app_info =
        g_dbus_node_info_new_for_xml(
            "<node>"
            "<interface name='org.freedesktop.DBus.ObjectManager'>"
            "<method name='GetManagedObjects'>"
            "<arg name='objects' "
            "type='a{oa{sa{sv}}}' "
            "direction='out'/>"
            "</method>"
            "</interface>"
            "</node>",
            &error
        );

    if (!app_info) {
        std::cerr
            << "Erro XML ObjectManager: "
            << error->message
            << std::endl;
        g_error_free(error);
        return;
    }

    g_dbus_connection_register_object(
        gatt_connection,
        GATT_APP_PATH,
        app_info->interfaces[0],
        &object_manager_vtable,
        nullptr,
        nullptr,
        &error
    );

    GDBusNodeInfo* service_info =
        g_dbus_node_info_new_for_xml(
            "<node>"
            "<interface name='org.bluez.GattService1'>"
            "<property name='UUID' type='s' access='read'/>"
            "<property name='Primary' type='b' access='read'/>"
            "</interface>"
            "</node>",
            &error
        );

    g_dbus_connection_register_object(
        gatt_connection,
        GATT_SERVICE_PATH,
        service_info->interfaces[0],
        &service_vtable,
        nullptr,
        nullptr,
        &error
    );

    GDBusNodeInfo* characteristic_info =
        g_dbus_node_info_new_for_xml(
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
            "</interface>"
            "</node>",
            &error
        );

    g_dbus_connection_register_object(
        gatt_connection,
        GATT_CHARACTERISTIC_PATH,
        characteristic_info->interfaces[0],
        &characteristic_vtable,
        nullptr,
        nullptr,
        &error
    );

    GDBusProxy* advertising_manager =
        g_dbus_proxy_new_sync(
            gatt_connection,
            G_DBUS_PROXY_FLAGS_NONE,
            nullptr,
            "org.bluez",
            "/org/bluez/hci0",
            "org.bluez.LEAdvertisingManager1",
            nullptr,
            &error
        );

    if (!advertising_manager) {

        std::cerr
            << "Erro LEAdvertisingManager: "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    GVariantBuilder advertising_options;

    g_variant_builder_init(
        &advertising_options,
        G_VARIANT_TYPE("a{sv}")
    );

    g_dbus_proxy_call(
        advertising_manager,
        "RegisterAdvertisement",
        g_variant_new(
            "(oa{sv})",
            ADVERTISEMENT_PATH,
            &advertising_options
        ),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        nullptr,
        on_advertisement_registered,
        nullptr
    );

    gatt_manager =
        g_dbus_proxy_new_sync(
            gatt_connection,
            G_DBUS_PROXY_FLAGS_NONE,
            nullptr,
            "org.bluez",
            "/org/bluez/hci0",
            "org.bluez.GattManager1",
            nullptr,
            &error
        );

    if (!gatt_manager) {

        std::cerr
            << "Erro GattManager: "
            << error->message
            << std::endl;

        g_error_free(error);
        return;
    }

    GVariantBuilder options;

    g_variant_builder_init(
        &options,
        G_VARIANT_TYPE("a{sv}")
    );

    g_dbus_proxy_call(
        gatt_manager,
        "RegisterApplication",
        g_variant_new(
            "(oa{sv})",
            GATT_APP_PATH,
            &options
        ),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        nullptr,
        on_gatt_registered,
        nullptr
    );

    g_main_loop_run(gatt_loop);
}

int legacy_main() {

    std::thread gatt_thread(start_gatt_server);

    std::cout
        << "A procurar candidatos a uplink..."
        << std::endl;

    auto adapters =
        SimpleBLE::Adapter::get_adapters();

    if (adapters.empty()) {

        std::cerr
            << "Nenhum adaptador encontrado."
            << std::endl;

        return 1;
    }

    auto adapter = adapters[0];

    std::cout
        << "Adaptador: "
        << adapter.identifier()
        << std::endl;

    adapter.scan_start();

    std::this_thread::sleep_for(
        std::chrono::seconds(5)
    );

    auto devices =
        adapter.scan_get_results();

    adapter.scan_stop();

    SimpleBLE::Peripheral candidate;
    bool found = false;

    for (auto& device : devices) {

        std::cout
            << "\nDISPOSITIVO: "
            << device.identifier()
            << " | "
            << device.address()
            << " | RSSI "
            << device.rssi()
            << " | connectable "
            << device.is_connectable()
            << std::endl;

        if (!device.is_connectable())
            continue;

        std::string name =
            device.identifier();

        if (name.find("SIC-NODE-A") ==
            std::string::npos)
            continue;

        candidate = device;
        found = true;

        std::cout
            << "\n=============================="
            << std::endl;

        std::cout
            << "CANDIDATO ENCONTRADO"
            << std::endl;

        std::cout
            << "Nome: "
            << name
            << std::endl;

        std::cout
            << "RSSI: "
            << device.rssi()
            << " dBm"
            << std::endl;

        std::cout
            << "=============================="
            << std::endl;

        break;
    }

    if (!found) {

        std::cerr
            << "Nenhum SIC-NODE-A encontrado."
            << std::endl;

        return 1;
    }

    std::cout << std::endl;
    std::cout << "UPLINK SELECIONADO" << std::endl;

    std::cout
        << "Nome: "
        << candidate.identifier()
        << std::endl;

    std::cout
        << "A estabelecer uplink..."
        << std::endl;

    try {

        candidate.connect();

        std::cout
            << "UPLINK ESTABELECIDO!"
            << std::endl;

        std::cout
            << "A procurar servico GATT SIC..."
            << std::endl;

        auto services =
            candidate.services();

        bool gatt_found = false;

        for (auto& service : services) {

            std::cout
                << "Servico: "
                << service.uuid()
                << std::endl;

            if (service.uuid() !=
                SIC_LINK_SERVICE_UUID)
                continue;

            gatt_found = true;

            std::cout
                << "SERVICO GATT SIC ENCONTRADO!"
                << std::endl;

            for (auto& characteristic :
                 service.characteristics()) {

                std::cout
                    << "Characteristic: "
                    << characteristic.uuid()
                    << std::endl;

                if (characteristic.uuid() !=
                    SIC_LINK_CHARACTERISTIC_UUID)
                    continue;

                SimpleBLE::ByteArray data = {
                    0x01,
                    0x01
                };

                std::cout
                    << "A registar UPLINK com NODE-A..."
                    << std::endl;

                candidate.write_request(
                    service.uuid(),
                    characteristic.uuid(),
                    data
                );

                std::cout
                    << "UPLINK DE CONTROLO ENVIADO!"
                    << std::endl;
            }
        }

        if (!gatt_found) {

            std::cout
                << "Servico GATT SIC nao encontrado."
                << std::endl;
        }

        std::cout << std::endl;

        std::cout
            << "B → A = UPLINK ATIVO"
            << std::endl;

        std::cout
            << "A → B = DOWNLINK DISPONIVEL"
            << std::endl;

        std::cout
            << "Carrega ENTER para terminar o teste..."
            << std::endl;

        std::cin.get();

        candidate.disconnect();

        std::cout
            << "Uplink terminado."
            << std::endl;

    } catch (const std::exception& e) {

        std::cerr
            << "Erro ao estabelecer uplink: "
            << e.what()
            << std::endl;
    }

    if (gatt_loop)
        g_main_loop_quit(gatt_loop);

    if (gatt_thread.joinable())
        gatt_thread.join();

    return 0;
}

static std::string load_nid() {
    const char* home = std::getenv("HOME");
    if (!home) {
        return {};
    }
    std::ifstream input(std::string(home) + "/.config/sic/nid");
    std::string value;
    std::getline(input, value);
    return value;
}

static std::uint32_t load_inbox_client() {
    const char* home = std::getenv("HOME");
    std::string path = std::string(home ? home : "") + "/.config/sic/inbox-client";
    {
        std::ifstream input(path);
        std::uint32_t value = 0;
        if (input >> value && value != 0) {
            return value;
        }
    }
    std::random_device source;
    std::uint32_t value = 0;
    while (value == 0) {
        value = (static_cast<std::uint32_t>(source()) << 16U) ^ source();
    }
    std::ofstream output(path, std::ios::trunc);
    output << value << std::endl;
    output.close();
    chmod(path.c_str(), S_IRUSR | S_IWUSR);
    return value;
}

static void stop_stale_discovery() {
    GError* error = nullptr;
    GDBusConnection* bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, nullptr, &error);
    if (!bus) {
        if (error) {
            g_error_free(error);
        }
        return;
    }
    GVariant* reply = g_dbus_connection_call_sync(
        bus,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.Adapter1",
        "StopDiscovery",
        nullptr,
        nullptr,
        G_DBUS_CALL_FLAGS_NONE,
        5000,
        nullptr,
        &error
    );
    if (reply) {
        g_variant_unref(reply);
    }
    if (error) {
        g_error_free(error);
    }
    g_object_unref(bus);
}

static void forget_device(const std::string& address) {
    if (address.empty()) {
        return;
    }
    std::string path = "/org/bluez/hci0/dev_" + address;
    for (char& character : path) {
        if (character == ':') {
            character = '_';
        }
    }
    GError* error = nullptr;
    GDBusConnection* bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, nullptr, &error);
    if (!bus) {
        if (error) {
            g_error_free(error);
        }
        return;
    }
    GVariant* reply = g_dbus_connection_call_sync(
        bus,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.Adapter1",
        "RemoveDevice",
        g_variant_new("(o)", path.c_str()),
        nullptr,
        G_DBUS_CALL_FLAGS_NONE,
        5000,
        nullptr,
        &error
    );
    if (reply) {
        g_variant_unref(reply);
    }
    if (error) {
        g_error_free(error);
    }
    g_object_unref(bus);
}

static void pause_downlink() {
    if (!gatt_connection) {
        return;
    }
    if (advertising_active.exchange(false)) {
        GError* error = nullptr;
        GVariant* reply = g_dbus_connection_call_sync(
            gatt_connection,
            "org.bluez",
            "/org/bluez/hci0",
            "org.bluez.LEAdvertisingManager1",
            "UnregisterAdvertisement",
            g_variant_new("(o)", ADVERTISEMENT_PATH),
            nullptr,
            G_DBUS_CALL_FLAGS_NONE,
            5000,
            nullptr,
            &error
        );
        if (reply) {
            g_variant_unref(reply);
        }
        if (error) {
            g_error_free(error);
        }
    }
    std::string device_path;
    {
        std::lock_guard<std::mutex> lock(topology_mutex);
        device_path = child_device_path;
    }
    if (!device_path.empty()) {
        GError* error = nullptr;
        GVariant* reply = g_dbus_connection_call_sync(
            gatt_connection,
            "org.bluez",
            device_path.c_str(),
            "org.bluez.Device1",
            "Disconnect",
            nullptr,
            nullptr,
            G_DBUS_CALL_FLAGS_NONE,
            5000,
            nullptr,
            &error
        );
        if (reply) {
            g_variant_unref(reply);
        }
        if (error) {
            g_error_free(error);
        }
    }
    notify_enabled = false;
}

static void resume_downlink() {
    if (!gatt_connection || advertising_active) {
        return;
    }
    GVariantBuilder options;
    g_variant_builder_init(&options, G_VARIANT_TYPE("a{sv}"));
    GError* error = nullptr;
    GVariant* reply = g_dbus_connection_call_sync(
        gatt_connection,
        "org.bluez",
        "/org/bluez/hci0",
        "org.bluez.LEAdvertisingManager1",
        "RegisterAdvertisement",
        g_variant_new("(oa{sv})", ADVERTISEMENT_PATH, &options),
        nullptr,
        G_DBUS_CALL_FLAGS_NONE,
        5000,
        nullptr,
        &error
    );
    if (reply) {
        g_variant_unref(reply);
        advertising_active = true;
        std::cout << "DOWNLINK REABERTO" << std::endl;
    }
    if (error) {
        std::cerr << "DOWNLINK PENDENTE: " << error->message << std::endl;
        g_error_free(error);
    }
}

int main(int argc, char** argv) {
    node_name = argc > 1 ? argv[1] : "SIC-NODE";
    std::string preferred_parent = argc > 2 ? argv[2] : "";
    recovery_parent_name = preferred_parent;
    node_nid = load_nid();
    if (node_nid.empty()) {
        std::cerr << "NID NAO CONFIGURADO" << std::endl;
        return 1;
    }
    inbox_client = load_inbox_client();
    try {
        const char* home = std::getenv("HOME");
        std::string links = std::string(home ? home : "") + "/.config/sic/links/";
        uplink_key = load_session_key(links + "uplink.key");
        uplink_sender = std::make_unique<sic::LinkSender>(uplink_key);
        uplink_receiver = std::make_unique<sic::LinkReceiver>(uplink_key);
        std::ifstream child_key_file(links + "downlink.key", std::ios::binary);
        if (child_key_file.good()) {
            child_key_file.close();
            auto key = load_session_key(links + "downlink.key");
            child_sender = std::make_unique<sic::LinkSender>(key);
            child_receiver = std::make_unique<sic::LinkReceiver>(key);
        }
    } catch (const std::exception& e) {
        std::cerr << "SEGURANCA NAO INICIALIZADA: " << e.what() << std::endl;
        return 1;
    }

    auto adapters = SimpleBLE::Adapter::get_adapters();
    if (adapters.empty()) {
        std::cerr << "ADAPTADOR BLE NAO ENCONTRADO" << std::endl;
        return 1;
    }
    auto adapter = adapters.front();
    std::cout << "NODE " << node_name << " NID " << node_nid << std::endl;
    std::cout << "A PROCURAR UPLINK" << std::endl;
    stop_stale_discovery();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    try {
        adapter.scan_for(6000);
    } catch (const std::exception& first_error) {
        std::cerr << "SCAN OCUPADO, A RECUPERAR: " << first_error.what() << std::endl;
        stop_stale_discovery();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        try {
            adapter.scan_for(6000);
        } catch (const std::exception& second_error) {
            std::cerr << "FALHA NO SCAN: " << second_error.what() << std::endl;
            return 2;
        }
    }

    SimpleBLE::Peripheral best;
    bool found = false;
    int best_hop = std::numeric_limits<int>::max();
    int best_rssi = std::numeric_limits<int>::min();
    auto select_candidate = [&]() {
        for (auto& device : adapter.scan_get_results()) {
            if (!device.is_connectable() || device.identifier().find("SIC") == std::string::npos) {
                continue;
            }
            if (!preferred_parent.empty() && device.identifier().find(preferred_parent) == std::string::npos) {
                continue;
            }
            for (const auto& entry : device.manufacturer_data()) {
                const auto& data = entry.second;
                if (data.size() < 3 || data[0] != 1 || (data[1] != 1 && data[1] != 2)) {
                    continue;
                }
                int candidate_hop = data[1] == 1 ? 1 : static_cast<int>(data[2]) + 1;
                if (!found || candidate_hop < best_hop ||
                    (candidate_hop == best_hop && device.rssi() > best_rssi)) {
                    best = device;
                    best_hop = candidate_hop;
                    best_rssi = device.rssi();
                    found = true;
                }
            }
        }
    };
    select_candidate();
    if (!found) {
        std::cout << "PARENT AINDA NAO VISIVEL, NOVA TENTATIVA" << std::endl;
        stop_stale_discovery();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        try {
            adapter.scan_for(8000);
            select_candidate();
        } catch (const std::exception& retry_error) {
            std::cerr << "FALHA NA SEGUNDA PROCURA: " << retry_error.what() << std::endl;
        }
    }
    if (!found) {
        std::cerr << "UPLINK SIC NAO ENCONTRADO" << std::endl;
        return 2;
    }
    if (recovery_parent_name.empty()) {
        recovery_parent_name = best.identifier();
    }
    try {
        best.connect();
        if (!best.is_connected()) {
            std::cerr << "FALHA NA LIGACAO AO UPLINK" << std::endl;
            return 3;
        }
        bool characteristic_found = false;
        for (auto service : best.services()) {
            if (service.uuid() != SIC_LINK_SERVICE_UUID) {
                continue;
            }
            for (auto characteristic : service.characteristics()) {
                if (characteristic.uuid() == SIC_LINK_CHARACTERISTIC_UUID) {
                    characteristic_found = true;
                }
            }
        }
        if (!characteristic_found) {
            std::cerr << "GATT SIC NAO ENCONTRADO" << std::endl;
            best.disconnect();
            return 4;
        }
        {
            std::lock_guard<std::mutex> lock(uplink_mutex);
            uplink = best;
            uplink_ready = true;
        }
        uplink.notify(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, handle_downlink);

        node_hop = best_hop;
        configured_hop = best_hop;
        root_child = best_hop == 1;
        uplink_name = best.identifier();
        last_heartbeat_ms = monotonic_ms();
        router_running = true;
        std::thread watchdog([] {
            bool timeout_reported = false;
            while (router_running) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto age = monotonic_ms() - last_heartbeat_ms.load();
                missed_heartbeats = age > 5000 ? static_cast<std::uint64_t>(age / 5000) : 0;
                if (age > 15000 && !timeout_reported) {
                    std::cerr << "HEARTBEAT TIMEOUT: uplink sem resposta" << std::endl;
                    node_hop = -1;
                    timeout_reported = true;
                }
                if (age > 15000 && (root_child || !uplink.is_connected())) {
                    reconnect_uplink();
                    std::this_thread::sleep_for(std::chrono::seconds(4));
                }
                if (age <= 15000) {
                    timeout_reported = false;
                }
            }
        });
        std::thread gatt_thread(start_gatt_server);
        for (int i = 0; i < 50 && !gatt_registered; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!gatt_registered) {
            std::cerr << "SERVIDOR GATT LOCAL NAO INICIOU" << std::endl;
            if (gatt_loop) {
                g_main_loop_quit(gatt_loop);
            }
            gatt_thread.join();
            router_running = false;
            watchdog.join();
            return 5;
        }
        std::thread dtls_thread(dtls_bridge_loop);

        sic::Frame registration{"REGISTER", node_nid, "SINK", "CONTROL", 0,
                                node_sequence++, node_name};
        send_uplink(sic::encode(registration));
        std::cout << "ROUTER ATIVO UPLINK=" << best.identifier()
                  << " HOP=" << node_hop << std::endl;
        std::cout << "COMANDOS: send <texto> | status | routes | network | security-test | quit" << std::endl;

        std::string command;
        while (std::getline(std::cin, command)) {
            if (command == "quit") {
                break;
            }
            if (command == "status") {
                std::lock_guard<std::mutex> lock(topology_mutex);
                std::cout << "NID=" << node_nid << std::endl;
                std::cout << "INBOX_CLIENT=" << inbox_client << std::endl;
                std::cout << "UPLINK_STATE=" << (node_hop >= 0 && uplink.is_connected() ? "ativo" : "inativo") << std::endl;
                std::cout << "UPLINK_NAME=" << uplink_name << std::endl;
                std::cout << "UPLINK_NID=" << (uplink_nid.empty() ? "desconhecido" : uplink_nid) << std::endl;
                std::cout << "HOP=" << node_hop << std::endl;
                std::cout << "DOWNLINKS=" << downlinks.size() << std::endl;
                for (const auto& nid : downlinks) {
                    std::cout << "DOWNLINK_NID=" << nid << std::endl;
                }
                std::cout << "HEARTBEATS_PERDIDOS=" << missed_heartbeats.load() << std::endl;
                std::cout << "ENCAMINHADAS_UPLINK=" << forwarded_uplink.load() << std::endl;
                std::cout << "ENCAMINHADAS_DOWNLINK=" << forwarded_downlink.load() << std::endl;
                continue;
            }
            if (command == "routes") {
                std::lock_guard<std::mutex> lock(topology_mutex);
                std::cout << "FORWARDING TABLE" << std::endl;
                std::cout << "SINK -> uplink" << std::endl;
                for (const auto& route : forwarding_table) {
                    std::cout << route.first << " -> " << route.second << std::endl;
                }
                continue;
            }
            if (command == "network") {
                std::cout << "NETWORK CONTROLS" << std::endl;
                std::cout << "parent=" << (preferred_parent.empty() ? "automatico" : preferred_parent) << std::endl;
                std::cout << "selection=menor_hop_depois_maior_RSSI" << std::endl;
                std::cout << "persistence=manter_enquanto_funcional" << std::endl;
                continue;
            }
            if (command == "security-test") {
                std::lock_guard<std::mutex> lock(uplink_mutex);
                sic::Frame frame{"DATA", node_nid, "SINK", "INBOX", inbox_client,
                                 node_sequence++, "teste anti-replay"};
                auto protected_frame = uplink_sender->protect(sic::bytes(sic::encode(frame)));
                uplink.write_request(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, protected_frame);
                uplink.write_request(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, protected_frame);
                protected_frame.back() ^= 0x01;
                uplink.write_request(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID, protected_frame);
                std::cout << "SECURITY TEST: original, replay e adulterada enviados" << std::endl;
                continue;
            }
            if (command.rfind("send ", 0) == 0) {
                sic::Frame frame{"DATA", node_nid, "SINK", "INBOX", inbox_client,
                                 node_sequence++, command.substr(5)};
                send_uplink(sic::encode(frame));
            }
        }

        {
            std::lock_guard<std::mutex> lock(uplink_mutex);
            uplink_ready = false;
        }
        router_running = false;
        watchdog.join();
        dtls_thread.join();
        if (gatt_loop) {
            g_main_loop_quit(gatt_loop);
        }
        gatt_thread.join();
        try {
            uplink.unsubscribe(SIC_LINK_SERVICE_UUID, SIC_LINK_CHARACTERISTIC_UUID);
            if (uplink.is_connected()) {
                uplink.disconnect();
            }
        } catch (const std::exception& e) {
            std::cerr << "AVISO AO TERMINAR UPLINK: " << e.what() << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "ERRO ROUTER: " << e.what() << std::endl;
        return 6;
    }
    return 0;
}
