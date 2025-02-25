#pragma once

#include "veins/veins.h"
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <memory>
#include <string>
#include <utility>
#include <gmpxx.h>


using namespace omnetpp;

namespace veins {

class VEINS_API MyVeinsApp : public DemoBaseApplLayer {
public:
    MyVeinsApp()
        : hr(nullptr, hcs_free_random),
          pk(nullptr, pcs_free_public_key),
          vk(nullptr, pcs_free_private_key) ,
          seed(0){}
    void initialize(int stage) override;
    void finish() override;

protected:
    void onBSM(DemoSafetyMessage* bsm) override;
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
private:

    std::unique_ptr<hcs_random, decltype(&hcs_free_random)> hr;
    std::unique_ptr<pcs_public_key, decltype(&pcs_free_public_key)> pk;
    std::unique_ptr<pcs_private_key, decltype(&pcs_free_private_key)> vk;
    unsigned long int seed;
    void initEncryptionEnv();


    std::pair<mpz_class, mpz_class> extractEncryptedCoordinates(const std::string &data);
};

} // namespace veins

