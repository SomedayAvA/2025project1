#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include "veins/modules/application/traci/Damgard.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
#include <chrono>
using namespace veins;

Define_Module(veins::Damgard);


// Helper Function: Initialize the encryption environment.
// It creates a random generator and generates a Paillier key pair
// with a fixed seed to ensure consistent keys.
typedef struct {
    mpz_t value;         // g^i mod mod
    unsigned long i;
} baby_step;

Damgard::~Damgard() {
    cancelAndDelete(sendMessageEvent);
}
void Damgard::initEncryptionEnv() {
    hcs_random* hr_raw = hcs_init_random();
    hr.reset(hr_raw);
    pk.reset(egcs_init_public_key());
    vk.reset(egcs_init_private_key());
    egcs_generate_key_pair(pk.get(), vk.get(), hr.get(), 2048);

}
void normalize_exponent(mpz_t result, mpz_t exponent, mpz_t mod) {
    mpz_t mod_minus_exp;
    mpz_init(mod_minus_exp);

    mpz_sub(mod_minus_exp, mod, exponent);
    if (mpz_cmp(exponent, mod_minus_exp) > 0) {
        mpz_set(result, mod_minus_exp);
    } else {
        mpz_set(result, exponent);
    }

    mpz_clear(mod_minus_exp);
}
// Helper Function: Extract encrypted coordinates from a string.
// The expected format is "x:<number>, y:<number>".
// Returns a pair (x, y) as mpz_class objects.
std::pair<mpz_class, mpz_class> Damgard::extractEncryptedCoordinates(const std::string &data)
{
    size_t posX = data.find("s:");
    size_t posY = data.find(", d:");
    std::string xStr = data.substr(posX + 2, posY - (posX + 2));
    std::string yStr = data.substr(posY + 4);
    return { mpz_class(xStr.c_str(), 10), mpz_class(yStr.c_str(), 10) };
}

void Damgard::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = -1;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 1.0, sendMessageEvent);
        initEncryptionEnv();
    }
    else if (stage == 1) {
        // Initialization dependent on other modules.
    }
}


void Damgard::finish()
{
    DemoBaseApplLayer::finish();

    if (encryptionCount > 0) {
        double avgEncryptionTime = totalEncryptionTime / encryptionCount;
        std::cout << " " << avgEncryptionTime << " ms" << std::endl;
    }
    if (decryptionCount > 0) {
        double avgDecryptionTime = totalDecryptionTime / decryptionCount;
        std::cout << " " << avgDecryptionTime << " ms" << std::endl;
    }
    if (computationCount > 0) {
        double avgComputationTime = totalComputationTime / computationCount;
        std::cout << " " << avgComputationTime << " ms" << std::endl;
    }


}

void egcs_sub(egcs_public_key *pk, egcs_cipher *result,
              egcs_cipher *ct1, egcs_cipher *ct2) {
    mpz_t inv_c1, inv_c2;
    mpz_inits(inv_c1, inv_c2, NULL);
    if (mpz_invert(inv_c1, ct2->c1, pk->q) == 0) {
        fprintf(stderr, "Error: Inversion of c1 failed.\n");
        exit(EXIT_FAILURE);
    }
    if (mpz_invert(inv_c2, ct2->c2, pk->q) == 0) {
        fprintf(stderr, "Error: Inversion of c2 failed.\n");
        exit(EXIT_FAILURE);
    }
    mpz_mul(result->c1, ct1->c1, inv_c1);
    mpz_mod(result->c1, result->c1, pk->q);
    mpz_mul(result->c2, ct1->c2, inv_c2);
    mpz_mod(result->c2, result->c2, pk->q);
    mpz_clears(inv_c1, inv_c2, NULL);
}
void Damgard::onBSM(DemoSafetyMessage* bsm)
{
    // Handle beacon messages from other vehicles or RSUs.
}
void compute_mod_inverse(mpz_t result, mpz_t base, mpz_t mod) {
    if (mpz_invert(result, base, mod) == 0) {
        printf("fail!\n");
    }
}
// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void Damgard::onWSM(BaseFrame1609_4* wsm) {

    // Cast the incoming message to our message type.
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string receivedData = receivedWSM->getDemoData();
    // If serial equals 1, this is a reply message containing encrypted differences.
    if (receivedWSM->getSerial() == 1) {
        std::cout << " distance: "  << std::endl;
        size_t posS = receivedData.find("s:(");
        size_t posSComma = receivedData.find(',', posS);
        size_t posS1 = receivedData.find(')', posS);
        mpz_class enc_remoteS_c1(receivedData.substr(posS + 3, posSComma - posS - 3).c_str());
        mpz_class enc_remoteS_c2(receivedData.substr(posSComma + 1, posS1 - posSComma - 1).c_str());
        size_t posD = receivedData.find(",d:(");
        size_t posDComma = receivedData.find(',', posD+5);
        size_t posD1 = receivedData.find(')', posD);
        mpz_class enc_remoteD_c1(receivedData.substr(posD + 4, posDComma - posD - 4).c_str());
        mpz_class enc_remoteD_c2(receivedData.substr(posDComma + 1, posD1 - posDComma - 1).c_str());

        egcs_cipher *remote_a1 = egcs_init_cipher();
        mpz_set(remote_a1->c1, enc_remoteS_c1.get_mpz_t());
        mpz_set(remote_a1->c2, enc_remoteS_c2.get_mpz_t());
        egcs_cipher *remote_a2 = egcs_init_cipher();
        mpz_set(remote_a2->c1, enc_remoteD_c1.get_mpz_t());
        mpz_set(remote_a2->c2, enc_remoteD_c2.get_mpz_t());

        mpz_t decrypted;
        mpz_init(decrypted);
        mpz_t decrypted1;
        mpz_init(decrypted1);
        mpz_t candidate, g_inv,candidate1;
        mpz_init(g_inv);
        mpz_init(candidate);
        mpz_init(candidate1);
        auto dec_start = std::chrono::high_resolution_clock::now();
        egcs_decrypt(vk.get(), decrypted, remote_a1);
        egcs_decrypt(vk.get(), decrypted1, remote_a2);
        if (mpz_invert(g_inv, pk->g, pk->q) == 0) {
            exit(1);
        }

        int found1 = 0, found2 = 0;
        long double d1,d2;
        for (int x = -1000; x <= 1000; x++) {
            if (x >= 0) {
                mpz_powm_ui(candidate, pk->g, x, pk->q);
                mpz_powm_ui(candidate1, pk->g, x, pk->q);
            } else {

                mpz_powm_ui(candidate, g_inv, -x, pk->q);
                mpz_powm_ui(candidate1, g_inv, -x, pk->q);
            }
            if (!found1 && mpz_cmp(candidate, decrypted) == 0) {
                d1 = x;
                found1 = 1;
            }
            if (!found2 && mpz_cmp(candidate1, decrypted1) == 0) {
                d2 = x;
                found2 = 1;
            }
            if (found1 && found2) {
                break;
            }
        }
        auto dec_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
        std::cout << "Decryption Time: " << dec_duration.count() << " ms" << std::endl;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;


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

        std::cout << " distance: " << minDistance << std::endl;
        return;
    }
    // Otherwise, the message contains encrypted coordinates.
    size_t posS = receivedData.find("s:(");
    size_t posD = receivedData.find(",d:(");
    size_t posG = receivedData.find(",g:");
    size_t posQ = receivedData.find(",q:");
    size_t posH = receivedData.find(",h:");

    // Extract encrypted s and d
    size_t posSComma = receivedData.find(',', posS); // Find comma in s:(c1,c2)
    size_t posDComma = receivedData.find(',', posD+5); // Find comma in d:(c1,c2)

    mpz_class enc_remoteS_c1(receivedData.substr(posS + 3, posSComma - posS - 3).c_str());
    mpz_class enc_remoteS_c2(receivedData.substr(posSComma + 1, posD - posSComma - 2).c_str());

    mpz_class enc_remoteD_c1(receivedData.substr(posD + 4, posDComma - posD - 4).c_str());
    mpz_class enc_remoteD_c2(receivedData.substr(posDComma + 1, posG - posDComma - 2).c_str());

    // Extract public key parameters
    mpz_class remote_g(receivedData.substr(posG + 3, posQ - posG - 3).c_str());
    mpz_class remote_q(receivedData.substr(posQ + 3, posH - posQ - 3).c_str());
    mpz_class remote_h(receivedData.substr(posH + 3).c_str());




    std::unique_ptr<egcs_public_key, void(*)(egcs_public_key*)> remote_pk(
        egcs_init_public_key(), [](egcs_public_key* k) { egcs_free_public_key(k); });

    // Set public key fields
    mpz_set(remote_pk->g, remote_g.get_mpz_t());
    mpz_set(remote_pk->q, remote_q.get_mpz_t());
    mpz_set(remote_pk->h, remote_h.get_mpz_t());



    // Encrypt the local vehicle's current coordinates.
    Coord currentPos = mobility->getPositionAt(simTime());
    FrenetCoord frenet = getFrenetCoordinates(currentPos);
    mpz_t m1, m2, plain1, plain2;
    mpz_inits(m1, m2, plain1, plain2, NULL);
    mpz_set_ui(m1, frenet.s);
    mpz_set_ui(m2, frenet.d);
    mpz_powm(plain1, remote_pk->g, m1, remote_pk->q);
    mpz_powm(plain2, remote_pk->g, m2, remote_pk->q);
    egcs_cipher* ct1 = egcs_init_cipher();
    egcs_cipher* ct2 = egcs_init_cipher();
    auto comp_start = std::chrono::high_resolution_clock::now();
    egcs_encrypt(remote_pk.get(), hr.get(), ct1, plain1);
    egcs_encrypt(remote_pk.get(), hr.get(), ct2, plain2);
    egcs_cipher *remote_a1 = egcs_init_cipher(); // Assuming library provides initialization function
    egcs_cipher *remote_a2 = egcs_init_cipher();
    mpz_set(remote_a1->c1, enc_remoteS_c1.get_mpz_t());
    mpz_set(remote_a1->c2, enc_remoteS_c2.get_mpz_t());
    mpz_set(remote_a2->c1, enc_remoteD_c1.get_mpz_t());
    mpz_set(remote_a2->c2, enc_remoteD_c2.get_mpz_t());
    egcs_cipher* sub_ct1 = egcs_init_cipher();
    egcs_cipher* sub_ct2 = egcs_init_cipher();
    egcs_sub(remote_pk.get(), sub_ct1, ct1, remote_a1);
    egcs_sub(remote_pk.get(), sub_ct2, ct2, remote_a2);
    auto comp_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> comp_duration = comp_end - comp_start;
    std::cout << "Computation Time: " << comp_duration.count() << " ms" << std::endl;
    totalComputationTime += comp_duration.count();
    computationCount++;

    std::ostringstream oss;
    oss << "s:(" << mpz_class(sub_ct1->c1).get_str() << "," << mpz_class(sub_ct1->c2).get_str() << ")"
    << ",d:(" << mpz_class(sub_ct2->c1).get_str() << "," << mpz_class(sub_ct2->c2).get_str() << ")";
    std::string replyStr = oss.str();
    TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
    populateWSM(replyMsg);
    replyMsg->setDemoData(replyStr.c_str());
    replyMsg->setSenderAddress(myId);
    replyMsg->setSerial(1);  // Mark the message as a reply.
    sendDown(replyMsg);
}


void Damgard::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}


void Damgard::handleSelfMsg(cMessage* msg)
{
    if (msg == sendMessageEvent) {
        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord frenet = getFrenetCoordinates(currentPos);
        std::cout <<  myId << std::endl;
        std::cout << "s = " << std::fixed << std::setprecision(1) << frenet.s << std::endl;
        std::cout << "d = " << std::fixed << std::setprecision(1) << frenet.d << std::endl;

        mpz_t m1, m2, plain1, plain2;
        mpz_inits(m1, m2, plain1, plain2, NULL);
        mpz_set_ui(m1, frenet.s);
        mpz_set_ui(m2, frenet.d);

        mpz_powm(plain1, pk->g, m1, pk->q);
        mpz_powm(plain2, pk->g, m2, pk->q);

        egcs_cipher* ct1 = egcs_init_cipher();
        egcs_cipher* ct2 = egcs_init_cipher();
        auto enc_start = std::chrono::high_resolution_clock::now();
        egcs_encrypt(pk.get(), hr.get(), ct1, plain1);
        egcs_encrypt(pk.get(), hr.get(), ct2, plain2);
        auto enc_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> enc_duration = enc_end - enc_start;
        std::cout << "Encryption Time: " << enc_duration.count() << " ms" << std::endl;


        totalEncryptionTime += enc_duration.count();
        encryptionCount++;

        mpz_class pk_q(pk.get()->q), pk_g(pk.get()->g),pk_h(pk.get()->h);


        std::ostringstream oss;
        oss << "s:(" << mpz_class(ct1->c1).get_str() << "," << mpz_class(ct1->c2).get_str() << ")"
            << ",d:(" << mpz_class(ct2->c1).get_str() << "," << mpz_class(ct2->c2).get_str() << ")"
            << ",g:" << pk_g.get_str()
            << ",q:" << pk_q.get_str()
            << ",h:" << pk_h.get_str();
        std::string posStr = oss.str();
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setDemoData(posStr.c_str());
        newWSM->setSenderAddress(myId);
        sendDown(newWSM);
        scheduleAt(simTime() + 1.0, sendMessageEvent);
    }
}



void Damgard::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Initialize the encryption environment.


    // Get the current position and encrypt the coordinates.

}
