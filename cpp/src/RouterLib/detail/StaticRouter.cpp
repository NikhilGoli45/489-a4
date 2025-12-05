#include "StaticRouter.h"

#include <spdlog/spdlog.h>
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
    , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    sr_ethernet_hdr_t* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    if (eth_type == ethertype_arp) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;
        sr_arp_hdr_t* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet || ntohs(arp_hdr->ar_pro) != ethertype_ip) return;

        uint16_t op = ntohs(arp_hdr->ar_op);
        uint32_t tip = arp_hdr->ar_tip;

        auto interface = routingTable->getRoutingInterface(iface);
        if (tip == interface.ip) {
            if (op == arp_op_request) {
                Packet reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
                auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
                auto* arp = reinterpret_cast<sr_arp_hdr_t*>(reply.data() + sizeof(sr_ethernet_hdr_t));

                std::memcpy(eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                std::memcpy(eth->ether_shost, interface.mac.data(), ETHER_ADDR_LEN);
                eth->ether_type = htons(ethertype_arp);

                arp->ar_hrd = arp_hdr->ar_hrd;
                arp->ar_pro = arp_hdr->ar_pro;
                arp->ar_hln = arp_hdr->ar_hln;
                arp->ar_pln = arp_hdr->ar_pln;
                arp->ar_op = htons(arp_op_reply);
                std::memcpy(arp->ar_sha, interface.mac.data(), ETHER_ADDR_LEN);
                arp->ar_sip = interface.ip;
                std::memcpy(arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                arp->ar_tip = arp_hdr->ar_sip;

                packetSender->sendPacket(reply, iface);
            } else if (op == arp_op_reply) {
                mac_addr sha;
                std::memcpy(sha.data(), arp_hdr->ar_sha, ETHER_ADDR_LEN);
                arpCache->addEntry(arp_hdr->ar_sip, sha);
            }
        }
    } else if (eth_type == ethertype_ip) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
        sr_ip_hdr_t* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        mac_addr src_mac;
        std::memcpy(src_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
        arpCache->addEntry(ip_hdr->ip_src, src_mac);

        if (ip_hdr->ip_hl < 5) return;
        size_t ip_header_len = ip_hdr->ip_hl * 4;
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + ip_header_len) return;

        uint16_t sum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        if (cksum(ip_hdr, ip_header_len) != sum) {
            spdlog::error("IP Checksum failed");
            return;
        }
        ip_hdr->ip_sum = sum;

        uint32_t dst = ip_hdr->ip_dst;
        bool is_for_us = false;
        for (const auto& [name, intf] : routingTable->getRoutingInterfaces()) {
            if (intf.ip == dst) {
                is_for_us = true;
                break;
            }
        }

        if (is_for_us) {
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                if (packet.size() < sizeof(sr_ethernet_hdr_t) + ip_header_len + sizeof(sr_icmp_hdr_t)) return;
                sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + ip_header_len);

                uint16_t icmp_sum = icmp_hdr->icmp_sum;
                icmp_hdr->icmp_sum = 0;
                size_t icmp_len = ntohs(ip_hdr->ip_len) - ip_header_len;
                if (cksum(icmp_hdr, icmp_len) != icmp_sum) {
                    spdlog::error("ICMP Checksum failed");
                    return;
                }
                icmp_hdr->icmp_sum = icmp_sum;

                if (icmp_hdr->icmp_type == 8 && icmp_hdr->icmp_code == 0) {
                    uint32_t src = ip_hdr->ip_src;
                    ip_hdr->ip_src = dst;
                    ip_hdr->ip_dst = src;
                    ip_hdr->ip_ttl = INIT_TTL;
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = cksum(ip_hdr, ip_header_len);

                    icmp_hdr->icmp_type = 0;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_len);

                    auto route = routingTable->getRoutingEntry(src);
                    if (route) {
                        uint32_t next_hop = route->gateway ? route->gateway : src;
                        auto mac = arpCache->getEntry(next_hop);
                        auto out_iface = routingTable->getRoutingInterface(route->iface);
                        std::memcpy(eth_hdr->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);

                        if (mac) {
                            std::memcpy(eth_hdr->ether_dhost, mac->data(), ETHER_ADDR_LEN);
                            packetSender->sendPacket(packet, route->iface);
                        } else {
                            arpCache->queuePacket(next_hop, packet, route->iface);
                        }
                    }
                }
            } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                 sendIcmp(packet, 3, 3);
            }
        } else {
            if (ip_hdr->ip_ttl <= 1) {
                sendIcmp(packet, 11, 0);
                return;
            }

            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, ip_header_len);

            auto route = routingTable->getRoutingEntry(dst);
            if (!route) {
                sendIcmp(packet, 3, 0);
                return;
            }

            uint32_t next_hop = route->gateway ? route->gateway : dst;
            auto mac = arpCache->getEntry(next_hop);
            auto out_iface = routingTable->getRoutingInterface(route->iface);
            std::memcpy(eth_hdr->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);

            if (mac) {
                std::memcpy(eth_hdr->ether_dhost, mac->data(), ETHER_ADDR_LEN);
                packetSender->sendPacket(packet, route->iface);
            } else {
                arpCache->queuePacket(next_hop, packet, route->iface);
            }
        }
    }
}

void StaticRouter::sendIcmp(const std::vector<uint8_t>& originalPacket, uint8_t type, uint8_t code) {
    if (originalPacket.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;

    const sr_ip_hdr_t* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(originalPacket.data() + sizeof(sr_ethernet_hdr_t));

    if (orig_ip->ip_p == ip_protocol_icmp) {
        size_t ip_header_len = orig_ip->ip_hl * 4;
        if (originalPacket.size() >= sizeof(sr_ethernet_hdr_t) + ip_header_len + sizeof(sr_icmp_hdr_t)) {
            const sr_icmp_hdr_t* icmp_hdr = reinterpret_cast<const sr_icmp_hdr_t*>(
                originalPacket.data() + sizeof(sr_ethernet_hdr_t) + ip_header_len);

            if (icmp_hdr->icmp_type == 3 || icmp_hdr->icmp_type == 4 || 
                icmp_hdr->icmp_type == 5 || icmp_hdr->icmp_type == 11 || 
                icmp_hdr->icmp_type == 12) {
                return;
            }
        }
    }

    uint32_t dest_ip = orig_ip->ip_src;

    auto route = routingTable->getRoutingEntry(dest_ip);
    if (!route) return;

    auto out_iface = routingTable->getRoutingInterface(route->iface);

    size_t icmp_data_len = sizeof(sr_ip_hdr_t) + 8;
    size_t total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    Packet response(total_len);
    sr_ethernet_hdr_t* eth = reinterpret_cast<sr_ethernet_hdr_t*>(response.data());
    sr_ip_hdr_t* ip = reinterpret_cast<sr_ip_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_ip);

    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p = ip_protocol_icmp;
    ip->ip_src = out_iface.ip;
    ip->ip_dst = dest_ip;
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->unused = 0;
    icmp->next_mtu = 0;
    std::memcpy(icmp->data, orig_ip, icmp_data_len);
    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

    uint32_t next_hop = route->gateway ? route->gateway : dest_ip;
    auto mac = arpCache->getEntry(next_hop);

    if (mac) {
        std::memcpy(eth->ether_dhost, mac->data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(response, route->iface);
    } else {
        arpCache->queuePacket(next_hop, response, route->iface);
    }
}
