/**
 * @file sessionParam.cpp
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2024-06-21
 *
 * @copyright Copyright (c) 2024
 *
 */

#include <json.hpp>
#include <ioctl_netif.h>
#include <map>
#include "logger.h"

#include "delayline.h"
#include "pvmain.h"

using namespace nlohmann;
using namespace std;

namespace ns_sess
{

    void to_json(json &to_j, map<string, ed137_call_t> &p)
    {
        char addr_ptr[20];

        json sessionArray;

        for (auto it : p)
        {

            pj_inet_ntop(PJ_AF_INET, &it.second.src_ip, addr_ptr, 20);
            string ipSrc = addr_ptr;

            pj_inet_ntop(PJ_AF_INET, &it.second.des_ip, addr_ptr, 20);
            string ipDst = addr_ptr;

            json ses = {{"id", it.second.id}};
            ses.push_back({"call_id", it.second.call_id});
            ses.push_back({"dstUri", it.second.dstUri});
            ses.push_back({"srcUri", it.second.srcUri});
            ses.push_back({"dstIp", ipDst});
            ses.push_back({"dstPort", it.second.des_port});
            ses.push_back({"srcIp", ipSrc});
            ses.push_back({"srcPort", it.second.src_port});
            ses.push_back({"delayLineFound", it.second.delayLineFound});
            sessionArray.push_back(ses);
            ses.clear();
        }
    to_j =sessionArray;
    }
    
}
