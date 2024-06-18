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
    bool autoRepeat;        // true = on
    bool direction;         // true = to_uas
    bool r2sDelay;          
    string userpart;

    vector<delayGroup> dgOn;    
    vector<delayGroup> dgOff;    
};

void from_json(const json& j, vector<delayLineParam> &p);
void printDelayLine ( vector <delayLineParam> &dlp );


}
