#include "StaticRouter.h"

#include <cstring>
#include <netinet/in.h>

#include "protocol.h"
#include "utils.h"

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache,
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
: routingTable(routingTable)
, packetSender(packetSender)
, arpCache(std::move(arpCache)) {}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    if (ntohs(eth->ether_type) != ethertype_ip) return;

    auto* ip = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    uint16_t sum = ip->ip_sum;
    ip->ip_sum = 0;
    if (cksum(ip, ip->ip_hl * 4) != sum) return;
    ip->ip_sum = sum;

    bool forUs = false;
    for (auto& [_, intf] : routingTable->getRoutingInterfaces()) {
        if (intf.ip == ip->ip_dst) forUs = true;
    }

    if (forUs) {
        if (ip->ip_p == ip_protocol_tcp || ip->ip_p == ip_protocol_udp) {
            sendIcmp(packet, 3, 3, iface);
        }
        return;
    }

    if (ip->ip_ttl <= 1) {
        sendIcmp(packet, 11, 0, iface);
        return;
    }

    auto route = routingTable->getRoutingEntry(ip->ip_dst);
    if (!route) {
        sendIcmp(packet, 3, 0, iface);
        return;
    }

    ip->ip_ttl--;
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, ip->ip_hl * 4);

    uint32_t nextHop = route->gateway ? route->gateway : ip->ip_dst;
    auto mac = arpCache->getEntry(nextHop);
    if (!mac) {
        arpCache->queuePacket(nextHop, packet, route->iface);
        return;
    }

    auto out_iface = routingTable->getRoutingInterface(route->iface);
    std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
    std::memcpy(eth->ether_dhost, mac->data(), ETHER_ADDR_LEN);
    packetSender->sendPacket(packet, route->iface);
}

void StaticRouter::sendIcmp(const std::vector<uint8_t>& originalPacket,
                            uint8_t type,
                            uint8_t code,
                            const std::string& iface_hint) {
    const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(originalPacket.data());
    const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(originalPacket.data() + sizeof(sr_ethernet_hdr_t));

    std::string out_iface_name;
    RoutingInterface out_iface;

    if (type == 3 && code == 3) {
        for (auto& [name, intf] : routingTable->getRoutingInterfaces()) {
            if (intf.ip == orig_ip->ip_dst) {
                out_iface_name = name;
                out_iface = intf;
            }
        }
    } else {
        out_iface_name = iface_hint;
        out_iface = routingTable->getRoutingInterface(iface_hint);
    }

    Packet response(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(response.data());
    auto* ip = reinterpret_cast<sr_ip_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t));
    auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
    std::memcpy(eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_ip);

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
    ip->ip_src = out_iface.ip;
    ip->ip_dst = orig_ip->ip_src;
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->unused = 0;
    icmp->next_mtu = 0;
    std::memcpy(icmp->data, orig_ip, sizeof(sr_ip_hdr_t) + 8);
    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

    packetSender->sendPacket(response, out_iface_name);
}
