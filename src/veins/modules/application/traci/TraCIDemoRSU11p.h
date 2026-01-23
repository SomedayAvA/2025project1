#ifndef VEINS_TRACIDEMORSU11P_H_
#define VEINS_TRACIDEMORSU11P_H_

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <omnetpp.h>

namespace veins {

class TraCIDemoRSU11p : public DemoBaseApplLayer {
  protected:
    cMessage* sendMessageTimer;
    simtime_t sendInterval;

    virtual void initialize(int stage) override;
    virtual void handleSelfMsg(cMessage* msg) override;
    virtual void finish() override;
    virtual void onWSA(DemoServiceAdvertisment* wsa) override;
    virtual void onWSM(BaseFrame1609_4* frame) override;

};
}
// namespace veins

#endif // VEINS_TRACIDEMORSU11P_H_
