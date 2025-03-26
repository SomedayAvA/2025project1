#pragma once

#include "veins/veins.h"
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <memory>
#include <string>
#include <utility>
#include <gmpxx.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

using namespace omnetpp;

namespace veins {

class VEINS_API RSAPP : public DemoBaseApplLayer {
public:

    virtual ~RSAPP();
    void initialize(int stage) override;
    void finish() override;

protected:
    void onBSM(DemoSafetyMessage* bsm) override;
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
    simtime_t lastDroveAt;
    bool sentMessage;
    int currentSubscribedServiceId;
private:


    cMessage* sendMessageEvent;
    double totalEncryptionTime = 0.0;  // 累计加密时间（毫秒）
    size_t encryptionCount = 0;        // 加密次数

    double totalDecryptionTime = 0.0;  // 累计解密时间（毫秒）
    size_t decryptionCount = 0;        // 解密次数
    RSA* rsa_public;
    RSA* rsa_private;

};

} // namespace veins

