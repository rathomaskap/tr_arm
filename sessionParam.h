/**
 * @file sessionParam.h
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2024-06-21
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef __SESSIONPARAM_H
#define __SESSIONPARAM_H

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

    void to_json(json &to_j, map<string, ed137_call_t> &p);
}

#endif