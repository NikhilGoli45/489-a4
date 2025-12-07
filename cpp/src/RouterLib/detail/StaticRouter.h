#ifndef STATICROUTER_H
#define STATICROUTER_H

#include <vector>
#include <memory>
#include <mutex>
#include <string>

#include "ArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "IStaticRouter.h"

class StaticRouter : public IStaticRouter {
public:
    StaticRouter(
        std::unique_ptr<ArpCache> arpCache,
        std::shared_ptr<IRoutingTable> routingTable,
        std::shared_ptr<IPacketSender> packetSender);

    void handlePacket(std::vector<uint8_t> packet, std::string iface) override;

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<ArpCache> arpCache;

    void sendIcmp(const std::vector<uint8_t>& originalPacket,
                  uint8_t type,
                  uint8_t code,
                  const std::string& iface_hint = "");
};

#endif // STATICROUTER_H
