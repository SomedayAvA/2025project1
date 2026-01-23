#include "veins/modules/application/traci/TraCIDemoRSU11p.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"

using namespace veins;

// 注册模块
Define_Module(TraCIDemoRSU11p);

void TraCIDemoRSU11p::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {

    }
}

void TraCIDemoRSU11p::handleSelfMsg(cMessage* msg) {

}

void TraCIDemoRSU11p::onWSA(DemoServiceAdvertisment* wsa) {
    //std::cout << "1111111111" << std::endl;

}

void TraCIDemoRSU11p::onWSM(BaseFrame1609_4* wsm) {
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    //std::cout<<receivedWSM->getSenderAddress()<<std::endl;
    TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
    populateWSM(newWSM);
    newWSM->setSenderAddress(receivedWSM->getSenderAddress());
    newWSM->setmessagetype(1);
    sendDown(newWSM);
}

void TraCIDemoRSU11p::finish() {
    cancelAndDelete(sendMessageTimer);
    DemoBaseApplLayer::finish();
}

