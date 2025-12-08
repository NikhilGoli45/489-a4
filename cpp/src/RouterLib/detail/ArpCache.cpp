#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <algorithm>
#include <spdlog/spdlog.h>
#include <netinet/in.h>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout,
    std::chrono::milliseconds tickInterval,
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender,
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::sendArpRequest(uint32_t ip, const std::string& iface) {
    try {
        auto routingInterface = routingTable->getRoutingInterface(iface);

        Packet packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        std::memset(packet.data(), 0, packet.size());

        auto* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
        auto* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

        std::memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
        std::memcpy(eth_hdr->ether_shost, routingInterface.mac.data(), ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_arp);

        arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        arp_hdr->ar_pro = htons(ethertype_ip);
        arp_hdr->ar_hln = ETHER_ADDR_LEN;
        arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = htons(arp_op_request);

        std::memcpy(arp_hdr->ar_sha, routingInterface.mac.data(), ETHER_ADDR_LEN);
        arp_hdr->ar_sip = routingInterface.ip;

        std::memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
        arp_hdr->ar_tip = ip;

        packetSender->sendPacket(packet, iface);
    } catch (const std::exception& e) {
        spdlog::error("Error sending ARP Request: {}", e.what());
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);

    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> timedOutIps;

    for (auto it = requests.begin(); it != requests.end(); ++it) {
        auto& request = it->second;

        if (now - request.lastSent >= resendInterval) {
            if (request.timesSent >= 7) {
                timedOutIps.push_back(request.ip);
            } else {
                sendArpRequest(request.ip, request.iface);
                request.lastSent = now;
                request.timesSent++;
            }
        }
    }

    for (uint32_t ip : timedOutIps) {
        auto node = requests.extract(ip);
        if (node.empty()) {
            continue;
        }
        auto& request = node.mapped();

        for (const auto& pkt : request.packets) {
            if (pkt.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
                continue;
            }

            auto* orig_eth = reinterpret_cast<sr_ethernet_hdr_t*>(
                const_cast<uint8_t*>(pkt.data()));
            auto* orig_ip = reinterpret_cast<sr_ip_hdr_t*>(
                const_cast<uint8_t*>(pkt.data()) + sizeof(sr_ethernet_hdr_t));

            uint32_t dest_ip = orig_ip->ip_src;

            try {
                auto out_iface = routingTable->getRoutingInterface(request.iface);

                size_t icmp_data_len = sizeof(sr_ip_hdr_t) + 8;
                size_t total_len = sizeof(sr_ethernet_hdr_t) +
                                   sizeof(sr_ip_hdr_t) +
                                   sizeof(sr_icmp_t3_hdr_t);

                Packet response(total_len);
                auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(response.data());
                auto* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(
                    response.data() + sizeof(sr_ethernet_hdr_t));
                auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(
                    response.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
                std::memcpy(eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
                eth->ether_type = htons(ethertype_ip);

                ip_hdr->ip_hl = 5;
                ip_hdr->ip_v = 4;
                ip_hdr->ip_tos = 0;
                ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
                ip_hdr->ip_id = 0;
                ip_hdr->ip_off = htons(IP_DF);
                ip_hdr->ip_ttl = INIT_TTL;
                ip_hdr->ip_p = ip_protocol_icmp;
                ip_hdr->ip_src = out_iface.ip;
                ip_hdr->ip_dst = dest_ip;
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

                icmp->icmp_type = 3;
                icmp->icmp_code = 1;
                icmp->unused = 0;
                icmp->next_mtu = 0;
                std::memcpy(icmp->data, orig_ip, icmp_data_len);
                icmp->icmp_sum = 0;
                icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

                packetSender->sendPacket(response, request.iface);
            } catch (const std::exception& e) {
                spdlog::error("Error sending ICMP Host Unreachable: {}", e.what());
            }
        }
    }

    std::erase_if(entries, [this, now](const auto& entry) {
        return now - entry.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    auto it = requests.find(ip);
    if (it == requests.end()) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    entries[ip] = {now, mac};

    for (auto& packet : it->second.packets) {
        if (packet.size() >= sizeof(sr_ethernet_hdr_t)) {
            auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
            std::memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);
            packetSender->sendPacket(packet, it->second.iface);
        }
    }

    requests.erase(it);
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    auto it = entries.find(ip);
    if (it != entries.end()) {
        return it->second.mac;
    }
    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    auto entryIt = entries.find(ip);
    if (entryIt != entries.end()) {
        if (packet.size() >= sizeof(sr_ethernet_hdr_t)) {
            Packet toSend = packet;
            auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(toSend.data());
            std::memcpy(eth->ether_dhost, entryIt->second.mac.data(), ETHER_ADDR_LEN);
            packetSender->sendPacket(toSend, iface);
        }
        return;
    }

    auto it = requests.find(ip);
    if (it != requests.end()) {
        it->second.packets.push_back(packet);
    } else {
        ArpRequest req;
        req.ip = ip;
        req.iface = iface;
        req.packets.push_back(packet);
        req.lastSent = std::chrono::steady_clock::now();
        req.timesSent = 1;
        requests[ip] = req;

        sendArpRequest(ip, iface);
    }
}
