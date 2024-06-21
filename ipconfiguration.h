/**
 * @file ipconfiguration.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2024-06-20
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <json.hpp>
#include <ioctl_netif.h>


using namespace nlohmann;

namespace ns_ip
{
    void from_json(const json &j, dnat_sip_proxy_h &dsp);
}
