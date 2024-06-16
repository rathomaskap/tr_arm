#include <json.hpp>
#include <ioctl_netif.h>
#include <vector>
#include "logger.h"

#include "delayline.h"

using namespace nlohmann;
using namespace std;

namespace ns_dl {


void from_json(const json& j, vector <delayLineParam> &dlp) {

delayLineParam dlTmp;

unsigned int ui;
string       str;

try{

for(auto it: j.at("dl")) {
        it.at("autoRepeat").get_to(str);
        dlTmp.autoRepeat = (str=="on") ? true : false;

        it.at("direction").get_to(str);
        dlTmp.autoRepeat = (str=="to_uas") ? true : false;

        delayGroup dgon; 

        for(auto jdg : it.at("onDelay"))
        {
            jdg.at("id").get_to(dgon.id);
            jdg.at("rep").get_to(dgon.rep);

            delayLine dl;

            for(auto jdv : jdg.at("delay"))
                {
                    string s;
                    jdv.at("id").get_to(dl.id);
                    jdv.at("value").get_to(s);
                    if(s=="drop") dl.value=128;
                    else if(s=="off") dl.value=64;
                    else dl.value=stoi(s);
                    dgon.dl.push_back(dl);
                }
            dgon.dl.push_back(dl);
        }
        
        dlTmp.dgOn.push_back(dgon);

        delayGroup dgoff;

        for(auto jdg : it.at("offDelay"))
        {
            jdg.at("id").get_to(dgoff.id);
            jdg.at("rep").get_to(dgoff.rep);

            delayLine dl;

            for(auto jdv : jdg.at("delay"))
                {
                    string s;
                    jdv.at("id").get_to(dl.id);
                    jdv.at("value").get_to(s);
                    if(s=="drop") dl.value=128;
                    else if(s=="off") dl.value=64;
                    else dl.value=stoi(s);
                    dgon.dl.push_back(dl);
                }
            dgoff.dl.push_back(dl);
        }
        dlTmp.dgOff.push_back(dgoff);
       
dlp.push_back(dlTmp);
}
}
catch(...)
{
    iprint(LOG_ERR,"converting json delayLine to Obj unsuccessful!");
}

}


void printDelayLine ( vector <delayLineParam> &dlp ) {
    iprint(LOG_INFO,"**** delayLIneParameter");
    for(auto ixdlp : dlp)
        {
            iprint(LOG_INFO,"-id:         %d\n",ixdlp.id);
            iprint(LOG_INFO,"-autoRepeat: %d\n",ixdlp.autoRepeat);
            iprint(LOG_INFO,"-direction:  %d\n",ixdlp.direction);


            for(auto ixdg : ixdlp.dgOn) {
                iprint(LOG_INFO,"-- delayline On\n");
                iprint(LOG_INFO,"-- dg ID:  %d\n",ixdg.id);
                iprint(LOG_INFO,"-- dg rep: %d\n",ixdg.rep);
                for(auto ixlg: ixdg.dl )    
                {
                iprint(LOG_INFO,"--- dl ID:     %d\n",ixlg.id);
                iprint(LOG_INFO,"--- dl value:  %d\n",ixlg.value);
                }
            }

            for(auto ixdg : ixdlp.dgOff) {
                iprint(LOG_INFO,"-- delayline Off\n");
                iprint(LOG_INFO,"-- dg ID:  %d\n",ixdg.id);
                iprint(LOG_INFO,"-- dg rep: %d\n",ixdg.rep);
                for(auto ixlg: ixdg.dl )    
                {
                iprint(LOG_INFO,"--- dl ID:     %d\n",ixlg.id);
                iprint(LOG_INFO,"--- dl value:  %d\n",ixlg.value);
                }
            }


        }
}



}