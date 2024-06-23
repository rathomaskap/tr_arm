

#include <json.hpp>
#include <ioctl_netif.h>
#include <vector>
#include "logger.h"
#include <sstream>      // std::stringstream

#include "delayline.h"

using namespace nlohmann;
using namespace std;

namespace ns_dl
{

    void from_json(const json &j, vector<delayLineParam> &dlp)
    {

        delayLineParam dlTmp;

        unsigned int ui;
        string str;

        try
        {

            for (auto it : j.at("dl"))
            {

                it.at("id").get_to(dlTmp.id);

                it.at("autoRepeat").get_to(str);
                dlTmp.autoRepeat = (str == "on") ? true : false;

                it.at("direction").get_to(str);
                dlTmp.direction = (str == "to_uas") ? true : false;

                it.at("userpart").get_to(dlTmp.userpart);

                it.at("r2sDelay").get_to(str);
                dlTmp.r2sDelay = (str == "on") ? true : false;

                delayGroup dgon;

                for (auto jdg : it.at("onDelay"))
                {
                    jdg.at("id").get_to(dgon.id);
                    jdg.at("rep").get_to(dgon.rep);

                    delayLine dl;

                    for (auto jdv : jdg.at("delay"))
                    {
                        string s;
                        jdv.at("id").get_to(dl.id);
                        jdv.at("value").get_to(s);
                        if (s == "drop")
                            dl.value = 128;
                        else if (s == "off")
                            dl.value = 64;
                        else
                            dl.value = stoi(s);
                        dgon.dl.push_back(dl);
                    }

                    dlTmp.dgOn.push_back(dgon);
                    dgon.dl.clear();
                }


                // berechne das int Array lineOn 

            
                    for (auto idgon : dlTmp.dgOn)
                    {
                        for (int i = 0; i < idgon.rep; i++)
                        {
                            for (auto idl : idgon.dl)
                            {
                                dlTmp.lineOn.push_back(idl.value);
                            }
                        }
                    }
                    iprint(LOG_INFO, "size of idlp: %d\n", dlTmp.lineOn.size());







                delayGroup dgoff;

                for (auto jdg : it.at("offDelay"))
                {
                    jdg.at("id").get_to(dgoff.id);
                    jdg.at("rep").get_to(dgoff.rep);

                    delayLine dl;

                    for (auto jdv : jdg.at("delay"))
                    {
                        string s;
                        jdv.at("id").get_to(dl.id);
                        jdv.at("value").get_to(s);
                        if (s == "drop")
                            dl.value = 128;
                        else if (s == "off")
                            dl.value = 64;
                        else
                            dl.value = stoi(s);
                        dgoff.dl.push_back(dl);
                    }
                    dlTmp.dgOff.push_back(dgoff);
                    dgoff.dl.clear();
                }


                // berechne das int Array lineOff 

            
                    for (auto idgoff : dlTmp.dgOff)
                    {
                        for (int i = 0; i < idgoff.rep; i++)
                        {
                            for (auto idl : idgoff.dl)
                            {
                                dlTmp.lineOff.push_back(idl.value);
                            }
                        }
                    }
                    iprint(LOG_INFO, "size of idlp: %d\n", dlTmp.lineOff.size());
                dlp.push_back(dlTmp);
            }
        }
        catch (...)
        {
            iprint(LOG_ERR, "converting json delayLine to Obj unsuccessful!");
        }
    }

    void printDelayLine(vector<delayLineParam> &dlp)
    {
        iprint(LOG_INFO, "**** delayLIneParameter");
        for (auto ixdlp : dlp)
        {
            iprint(LOG_INFO, "-id:         %d\n", ixdlp.id);
            iprint(LOG_INFO, "-userpart:   %s\n", ixdlp.userpart.c_str());
            iprint(LOG_INFO, "-autoRepeat: %d\n", ixdlp.autoRepeat);
            iprint(LOG_INFO, "-direction:  %d\n", ixdlp.direction);
            iprint(LOG_INFO, "-r2sDelay:   %d\n", ixdlp.r2sDelay);

            iprint(LOG_INFO, "-- delayline On\n");
            for (auto ixdg : ixdlp.dgOn)
            {
                iprint(LOG_INFO, "-- dg ID:  %d  dg rep: %d\n", ixdg.id, ixdg.rep);
                for (auto ixlg : ixdg.dl)
                {
                    iprint(LOG_INFO, "--- dl ID:     %d    dl value:  %d\n", ixlg.id, ixlg.value);
                }
            }


            std::stringstream son;
            son << "--- Array: ";
            for (auto iline : ixdlp.lineOn)
            {

                son << " " << iline;

                // iprint(LOG_INFO, " %d", iline);
            }

            iprint(LOG_INFO, " %s", son.str().c_str());


            iprint(LOG_INFO, "-- delayline Off\n");
            for (auto ixdg : ixdlp.dgOff)
            {
                iprint(LOG_INFO, "-- dg ID:  %d  dg rep: %d\n", ixdg.id, ixdg.rep);
                for (auto ixlg : ixdg.dl)
                {
                    iprint(LOG_INFO, "--- dl ID:     %d    dl value:  %d\n", ixlg.id, ixlg.value);
                }
            }
            std::stringstream soff;
            soff << "--- Array: ";

            for (auto iline : ixdlp.lineOff)
            {
                soff << " " << iline;
                
                // iprint(LOG_INFO, " %d", iline);
            }
             iprint(LOG_INFO, "%s", soff.str().c_str());
        }
    }

}