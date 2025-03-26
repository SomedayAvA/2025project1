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
    mpz_t value;         // 存储 g^i mod mod 的值
    unsigned long i;     // 指数 i
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

    mpz_sub(mod_minus_exp, mod, exponent);  // 计算 mod - exponent
    if (mpz_cmp(exponent, mod_minus_exp) > 0) {
        mpz_set(result, mod_minus_exp);  // 取较小的值
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
        std::cout << "平均加密时间: " << avgEncryptionTime << " ms" << std::endl;
    }
    if (decryptionCount > 0) {
        double avgDecryptionTime = totalDecryptionTime / decryptionCount;
        std::cout << "平均解密时间: " << avgDecryptionTime << " ms" << std::endl;
    }
    if (computationCount > 0) {
        double avgComputationTime = totalComputationTime / computationCount;
        std::cout << "平均计算时间: " << avgComputationTime << " ms" << std::endl;
    }

    // 你也可以在此处记录或保存其它统计数据
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
        printf("模反演失败，base 在 mod 下没有逆元！\n");
    }
}
// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void Damgard::onWSM(BaseFrame1609_4* wsm) {
    // Initialize the encryption environment.
    /*mpz_t m1, m2, plain1, plain2;
    mpz_inits(m1, m2, plain1, plain2, NULL);
    mpz_set_ui(m1, 1000);
    mpz_set_ui(m2, 1999);
    mpz_powm(plain1, pk->g, m1, pk->q);
    mpz_powm(plain2, pk->g, m2, pk->q);

    // ---------------------------
    // 加密操作
    // ---------------------------
    egcs_cipher* ct1 = egcs_init_cipher();
    egcs_cipher* ct2 = egcs_init_cipher();
    egcs_encrypt(pk.get(), hr.get(), ct1, plain1);
    egcs_encrypt(pk.get(), hr.get(), ct2, plain2);

    // ---------------------------
    // 同态减法：计算 E(g^(10)) / E(g^(3)) = E(g^(7))
    // ---------------------------
    egcs_cipher* sub_ct = egcs_init_cipher();
    egcs_sub(pk.get(), sub_ct, ct1, ct2);

    // ---------------------------
    // 解密同态减法结果：得到 g^7 mod q
    // ---------------------------
    mpz_t decrypted;
    mpz_init(decrypted);
    egcs_decrypt(vk.get(), decrypted, sub_ct);

    // ---------------------------
    // 使用Baby-step Giant-step算法恢复指数 m （应恢复为7）
    // ---------------------------

    // 假设消息 m 在 [0, 1000) 内搜索
    mpz_t expected, diff;
    mpz_inits(expected, diff, NULL);
    mpz_sub(diff, m1, m2);  // diff = m1 - m2
    mpz_powm(expected, pk->g, diff, pk->q);

    // ---------------------------
    // 输出结果
    // ---------------------------
    gmp_printf("解密结果: %Zd\n", decrypted);
    gmp_printf("预期结果: %Zd\n", expected);
    mpz_t candidate, g_inv;
    mpz_inits(candidate, g_inv, NULL);
    auto start = std::chrono::high_resolution_clock::now();
    // 计算 g 在模 pk->q 下的逆元，用于处理负指数
    if (mpz_invert(g_inv, pk->g, pk->q) == 0) {
        printf("g 没有逆元，无法进行暴力搜索。\n");
        exit(1);
    }

    int found = 0;
    for (int x = -1000; x <= 1000; x++) {
        if (x >= 0) {
            mpz_powm_ui(candidate, pk->g, x, pk->q);
        } else {
            // 负指数: 计算 (g^{-1})^{|x|} mod pk->q
            mpz_powm_ui(candidate, g_inv, -x, pk->q);
        }
        if (mpz_cmp(candidate, decrypted) == 0) {
            printf("找到离散对数: %d\n", x);
            found = 1;
            break;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "耗时: " << duration.count() << " 毫秒" << std::endl;
    if (!found) {
        printf("在给定范围内未找到离散对数。\n");
    }*/
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

        egcs_cipher *remote_a1 = egcs_init_cipher(); // 假设库提供初始化函数
        mpz_set(remote_a1->c1, enc_remoteS_c1.get_mpz_t());
        mpz_set(remote_a1->c2, enc_remoteS_c2.get_mpz_t());
        egcs_cipher *remote_a2 = egcs_init_cipher(); // 假设库提供初始化函数
        mpz_set(remote_a2->c1, enc_remoteD_c1.get_mpz_t());
        mpz_set(remote_a2->c2, enc_remoteD_c2.get_mpz_t());
        // 定义一个 mpz_class 用于存放解密后的明文
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
        std::cout << "解密时间: " << dec_duration.count() << " ms" << std::endl;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;
        /*auto diffPair = extractEncryptedCoordinates(receivedData);
        mpz_class diff1 = diffPair.first;
        mpz_class diff2 = diffPair.second;
        auto dec_start = std::chrono::high_resolution_clock::now();
        // Decrypt the differences.
        egcs_decrypt(vk.get(), diff1.get_mpz_t(), diff1.get_mpz_t());
        egcs_decrypt(vk.get(), diff2.get_mpz_t(), diff2.get_mpz_t());
        auto dec_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
        std::cout << "解密时间: " << dec_duration.count() << " ms" << std::endl;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;
        // Adjust if using a Z_n representation with negatives.
        mpz_class n_val(pk.get()->n);
        mpz_class half_n = n_val / 2;
        if(diff1 > half_n)
            diff1 -= n_val;
        if(diff2 > half_n)
            diff2 -= n_val;

        // Calculate the Euclidean distance.
        long double d1 = diff1.get_d();
        long double d2 = diff2.get_d();*/

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

    // 提取加密的 s 和 d
    size_t posSComma = receivedData.find(',', posS); // 找到 s:(c1,c2) 中的逗号
    size_t posDComma = receivedData.find(',', posD+5); // 找到 d:(c1,c2) 中的逗号

    mpz_class enc_remoteS_c1(receivedData.substr(posS + 3, posSComma - posS - 3).c_str());
    mpz_class enc_remoteS_c2(receivedData.substr(posSComma + 1, posD - posSComma - 2).c_str());

    mpz_class enc_remoteD_c1(receivedData.substr(posD + 4, posDComma - posD - 4).c_str());
    mpz_class enc_remoteD_c2(receivedData.substr(posDComma + 1, posG - posDComma - 2).c_str());

    // 提取公钥参数
    mpz_class remote_g(receivedData.substr(posG + 3, posQ - posG - 3).c_str());
    mpz_class remote_q(receivedData.substr(posQ + 3, posH - posQ - 3).c_str());
    mpz_class remote_h(receivedData.substr(posH + 3).c_str());




    std::unique_ptr<egcs_public_key, void(*)(egcs_public_key*)> remote_pk(
        egcs_init_public_key(), [](egcs_public_key* k) { egcs_free_public_key(k); });

    // 设置公钥字段
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
    egcs_cipher *remote_a1 = egcs_init_cipher(); // 假设库提供初始化函数
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
    std::cout << "计算时间: " << comp_duration.count() << " ms" << std::endl;\
    totalComputationTime += comp_duration.count();
    computationCount++;
    /*mpz_class localX(frenet.s), localY(frenet.d);
    egcs_cipher *enc_a1 = egcs_init_cipher(); // 假设库提供初始化函数
    egcs_cipher *enc_a2 = egcs_init_cipher();
    auto comp_start = std::chrono::high_resolution_clock::now();
    egcs_encrypt(remote_pk.get(), hr.get(), enc_a1, localX.get_mpz_t());
    egcs_encrypt(remote_pk.get(), hr.get(), enc_a2, localY.get_mpz_t());

    // Compute the homomorphic difference:
    egcs_cipher* homomorphic_diff = egcs_init_cipher();

    // 1. 计算 enc_a1 的逆元（需分别处理 c1/c2）
    egcs_cipher enc_a1_inv;
    mpz_inits(enc_a1_inv.c1, enc_a1_inv.c2, NULL);

    // 计算 c1 的逆元（模 pk->q）
    if (mpz_invert(enc_a1_inv.c1, enc_a1->c1, remote_pk->q) == 0) {
        EV_ERROR << "无法计算 c1 的逆元\n";
        return;
    }

    // 计算 c2 的逆元（模 pk->q）
    if (mpz_invert(enc_a1_inv.c2, enc_a1->c2, remote_pk->q) == 0) {
        EV_ERROR << "无法计算 c2 的逆元\n";
        return;
    }

    // 2. 执行同态乘法：remote_a1 * enc_a1^{-1}
    egcs_ee_mul(remote_pk.get(), homomorphic_diff, remote_a1, &enc_a1_inv);*/

    // 3. 验证计算结果（可选）
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
        std::cout << "本次加密时间: " << enc_duration.count() << " ms" << std::endl;

        // 累积加密时间和计数
        totalEncryptionTime += enc_duration.count();
        encryptionCount++;
        /*mpz_class a1(frenet.s), a2(frenet.d);
        // 检查加密库是否需要显式初始化
        egcs_cipher *enc_a1 = egcs_init_cipher(); // 假设库提供初始化函数
        egcs_cipher *enc_a2 = egcs_init_cipher();

        // 开始计时 - 加密时间
       auto enc_start = std::chrono::high_resolution_clock::now();
       // 在调用前添加检查

        // 执行加密操作
        egcs_encrypt(pk.get(), hr.get(), enc_a1, a1.get_mpz_t());
        egcs_encrypt(pk.get(), hr.get(), enc_a2, a2.get_mpz_t());

        // 结束计时
        auto enc_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> enc_duration = enc_end - enc_start;
        std::cout << "本次加密时间: " << enc_duration.count() << " ms" << std::endl;

        // 累积加密时间和计数
        totalEncryptionTime += enc_duration.count();
        encryptionCount++;*/

        // 构造消息并发送
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
