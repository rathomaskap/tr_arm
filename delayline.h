/**
 * @file delayline.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2024-06-21
 * 
 * @copyright Copyright (c) 2024
 * 
 */


#ifndef __DELAYLINE_H
#define __DELAYLINE_H

#include <vector>
#include <string>
#include <json.hpp>
using namespace nlohmann;

using namespace std;

    
// namespace std;


namespace ns_dl {


struct delayLine {
    unsigned int id;
    unsigned int value;
};

struct delayGroup {
    unsigned int id;
    unsigned int rep;       // wie oft wir die Gruppe wiederholt
    vector<delayLine> dl;
};

struct delayLineParam {
    unsigned int id;
    bool autoRepeatOn;        // true = on
    bool autoRepeatOff;        // true = on

    bool direction;         // true = to_uas
    bool r2sDelay;          
    string dstUserPart;
    string srcUserPart;

    vector<delayGroup> dgOn;    
    vector<delayGroup> dgOff;    
    vector<int> lineOn;
    vector<int> lineOff;
};

void from_json(const json& j, vector<delayLineParam> &p);
void printDelayLine ( vector <delayLineParam> &dlp );


}


#endif