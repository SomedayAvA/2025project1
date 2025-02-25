#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include "veins/modules/application/traci/MyVeinsApp.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using namespace veins;

Define_Module(veins::MyVeinsApp);


// Helper Function: Initialize the encryption environment.
// It creates a random generator and generates a Paillier key pair
// with a fixed seed to ensure consistent keys.
void MyVeinsApp::initEncryptionEnv() {
    hcs_random* hr_raw = hcs_init_random();
    hr.reset(hr_raw);
    pk.reset(pcs_init_public_key());
    vk.reset(pcs_init_private_key());
    pcs_generate_key_pair(pk.get(), vk.get(), hr.get(), 2048);

}

// Helper Function: Extract encrypted coordinates from a string.
// The expected format is "x:<number>, y:<number>".
// Returns a pair (x, y) as mpz_class objects.
std::pair<mpz_class, mpz_class> MyVeinsApp::extractEncryptedCoordinates(const std::string &data)
{
    size_t posX = data.find("s:");
    size_t posY = data.find(", d:");
    std::string xStr = data.substr(posX + 2, posY - (posX + 2));
    std::string yStr = data.substr(posY + 4);
    return { mpz_class(xStr.c_str(), 10), mpz_class(yStr.c_str(), 10) };
}

void MyVeinsApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        // Initialize basic members and pointers.
        initEncryptionEnv();
    }
    else if (stage == 1) {
        // Initialization dependent on other modules.
    }
}


void MyVeinsApp::finish()
{
    DemoBaseApplLayer::finish();
    // Additional statistics recording can go here.
}


void MyVeinsApp::onBSM(DemoSafetyMessage* bsm)
{
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void MyVeinsApp::onWSM(BaseFrame1609_4* wsm) {
    // Initialize the encryption environment.

    // Cast the incoming message to our message type.
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string receivedData = receivedWSM->getDemoData();

    // If serial equals 1, this is a reply message containing encrypted differences.
    if (receivedWSM->getSerial() == 1) {
        auto diffPair = extractEncryptedCoordinates(receivedData);
        mpz_class diff1 = diffPair.first;
        mpz_class diff2 = diffPair.second;

        // Decrypt the differences.
        pcs_decrypt(vk.get(), diff1.get_mpz_t(), diff1.get_mpz_t());
        pcs_decrypt(vk.get(), diff2.get_mpz_t(), diff2.get_mpz_t());

        // Adjust if using a Z_n representation with negatives.
        mpz_class n_val(pk.get()->n);
        mpz_class half_n = n_val / 2;
        if(diff1 > half_n)
            diff1 -= n_val;
        if(diff2 > half_n)
            diff2 -= n_val;

        // Calculate the Euclidean distance.
        long double d1 = diff1.get_d();
        long double d2 = diff2.get_d();
        long double distance = std::sqrt(d1 * d1 + d2 * d2);
        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord originalFrenet = getFrenetCoordinates(currentPos);
        const std::array<std::pair<double, double>, 4> candidates = {{
            {originalFrenet.s + d1, originalFrenet.d + d2}, // s+d1, d+d2
            {originalFrenet.s + d1, originalFrenet.d - d2}, // s+d1, d-d2
            {originalFrenet.s - d1, originalFrenet.d + d2}, // s-d1, d+d2
            {originalFrenet.s - d1, originalFrenet.d - d2}  // s-d1, d-d2
        }};
        double minDistance = std::numeric_limits<double>::max();
        Coord bestCoord;
        for (const auto& candidate : candidates) {
            double s_candidate = candidate.first;
            double d_candidate = candidate.second;
            Coord cartesianCandidate = getCartesianFromFrenet(s_candidate, d_candidate);

            double dx = cartesianCandidate.x - currentPos.x;
            double dy = cartesianCandidate.y - currentPos.y;
            double distance = std::hypot(dx, dy);
            if (distance < minDistance) {
                minDistance = distance;
                bestCoord = cartesianCandidate;
            }
        }

        // 输出最终结果
        std::cout << " distance: " << minDistance << std::endl;
        return;
    }

    // Otherwise, the message contains encrypted coordinates.
    size_t posS    = receivedData.find("s:");
    size_t posD    = receivedData.find(",d:");
    size_t posN    = receivedData.find(",n:");
    size_t posG    = receivedData.find(",g:");



    mpz_class enc_remoteX(receivedData.substr(posS+2, posD-posS-2).c_str());
    mpz_class enc_remoteY(receivedData.substr(posD+3, posN-posD-3).c_str());
    mpz_class remote_n(receivedData.substr(posN+3, posG-posN-3).c_str());
    mpz_class remote_g(receivedData.substr(posG + 3).c_str());



    std::unique_ptr<pcs_public_key, void(*)(pcs_public_key*)> remote_pk(pcs_init_public_key(), [](pcs_public_key* k){ pcs_free_public_key(k); });
    mpz_set(remote_pk->n, remote_n.get_mpz_t());
    mpz_set(remote_pk->g, remote_g.get_mpz_t());
    mpz_pow_ui(remote_pk->n2, remote_pk->n, 2);

    std::cout << "Receiver Vehicle[" << myId << "] received encrypted coordinates from Vehicle["
              << receivedWSM->getSenderAddress() << "]: s = " << enc_remoteX
              << ", d = " << enc_remoteY << std::endl;

    // Encrypt the local vehicle's current coordinates.
    Coord currentPos = mobility->getPositionAt(simTime());
    FrenetCoord frenet = getFrenetCoordinates(currentPos);
    mpz_class localX(frenet.s), localY(frenet.d);
    mpz_class enc_localX = localX, enc_localY = localY;
    pcs_encrypt(remote_pk.get(), hr.get(), enc_localX.get_mpz_t(), enc_localX.get_mpz_t());
    pcs_encrypt(remote_pk.get(), hr.get(), enc_localY.get_mpz_t(), enc_localY.get_mpz_t());

    // Compute the homomorphic difference:
    // Enc(remote - local) = Enc(remote) * (Enc(local))^{-1} mod n^2.
    mpz_class inv_enc_localX, inv_enc_localY;
    mpz_invert(inv_enc_localX.get_mpz_t(), enc_localX.get_mpz_t(), remote_pk.get()->n2);
    if (mpz_invert(inv_enc_localY.get_mpz_t(), enc_localY.get_mpz_t(), remote_pk.get()->n2) == 0) {
        EV_ERROR << "Vehicle[" << myId << "]: Inversion for enc_localY failed!\n";
        return;
    }
    mpz_class enc_diffX, enc_diffY;
    mpz_mul(enc_diffX.get_mpz_t(), enc_remoteX.get_mpz_t(), inv_enc_localX.get_mpz_t());
    mpz_mod(enc_diffX.get_mpz_t(), enc_diffX.get_mpz_t(), remote_pk.get()->n2);
    mpz_mul(enc_diffY.get_mpz_t(), enc_remoteY.get_mpz_t(), inv_enc_localY.get_mpz_t());
    mpz_mod(enc_diffY.get_mpz_t(), enc_diffY.get_mpz_t(), remote_pk.get()->n2);

    // Build a reply message containing the encrypted differences.
    std::ostringstream oss;
    oss << "s:" << enc_diffX << ", d:" << enc_diffY;
    std::string replyStr = oss.str();
    TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
    populateWSM(replyMsg);
    replyMsg->setDemoData(replyStr.c_str());
    replyMsg->setSenderAddress(myId);
    replyMsg->setSerial(1);  // Mark the message as a reply.
    std::cout << "Receiver Vehicle[" << myId << "] sending encrypted difference reply to Vehicle["
              << receivedWSM->getSenderAddress() << "]: " << replyStr << std::endl;
    sendDown(replyMsg);
}


void MyVeinsApp::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}
void MyVeinsApp::handleSelfMsg(cMessage* msg)
{
    DemoBaseApplLayer::handleSelfMsg(msg);
    // Additional self-message handling can be added here.
}


void MyVeinsApp::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Initialize the encryption environment.

    num++; //
    if (num % 2 == 0) {
    // Get the current position and encrypt the coordinates.
    Coord currentPos = mobility->getPositionAt(simTime());
    FrenetCoord frenet = getFrenetCoordinates(currentPos);
    std::cout <<  myId << std::endl;
    std::cout << "s = " << std::fixed << std::setprecision(1) << frenet.s << std::endl;
    std::cout << "d = " << std::fixed << std::setprecision(1) << frenet.d << std::endl;
    mpz_class a1(frenet.s), a2(frenet.d);
    mpz_class enc_a1 = a1, enc_a2 = a2;
    pcs_encrypt(pk.get(), hr.get(), enc_a1.get_mpz_t(), enc_a1.get_mpz_t());
    pcs_encrypt(pk.get(), hr.get(), enc_a2.get_mpz_t(), enc_a2.get_mpz_t());
    // Format the encrypted coordinates into a string.
    mpz_class pk_n(pk.get()->n), pk_g(pk.get()->g);
    std::ostringstream oss;
    oss << "s:" << enc_a1 << ",d:" << enc_a2
        << ",n:" << pk_n.get_str()
        << ",g:" << pk_g.get_str();
    std::string posStr = oss.str();
    TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
    populateWSM(newWSM);
    newWSM->setDemoData(posStr.c_str());
    newWSM->setSenderAddress(myId);
    //newWSM->setHr(seed);
    sendDown(newWSM);
    }

}
