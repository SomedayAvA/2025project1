#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include <utility>
#include <vector>
#include <array>
#include <chrono>
#include <string>
#include <limits>
#include <sstream>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include<openssl/rand.h>
#include <openssl/pem.h>
#include "Interfaces.pb.h"
#include <google/protobuf/util/json_util.h>
#include "curve_utils.h"
#include "veins/modules/mac/ieee80211p/Mac1609_4.h"
#include "veins/modules/application/traci/emergency.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;
using namespace veins;
using namespace bigintdyn;

Define_Module(veins::emergency);

// Global CKKS crypto context and initialization flag.

//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
emergency::~emergency() {
    cancelAndDelete(sendMessageEvent);
}

// Called at different initialization stages of the simulation.
void emergency::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        std::string vehId = mobility->getExternalId();
        vehicleEntryTimes[vehId] = simTime();
        std::string myType = traciVehicle->getVType();
        /*if(myType=="ambulance")
        {
            TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
            traciVehicle.setSpeedMode(96);
            //std::cout << "1111111111" << std::endl;
        }*/
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}


void emergency::finish() {
    DemoBaseApplLayer::finish();

    std::string vehId = mobility->getExternalId();
    simtime_t exitTime = simTime();

    if (vehicleEntryTimes.find(vehId) != vehicleEntryTimes.end()) {
        simtime_t lifetime = exitTime - vehicleEntryTimes[vehId];
        vehicleLifetimes.push_back(lifetime);
    }

    // Original position recording (kept unchanged)
    auto pos = mobility->getPositionAt(simTime());
    std::cout << myId<<pos << std::endl;
        std::ofstream outFile("position.txt", std::ios::app);
        if (outFile.is_open()) {
            outFile << pos << std::endl;
            outFile.close();
        } else {
            std::cerr << "Cannot open file position.txt" << std::endl;
        }

    // Calculate average time and record to file
    double avgLifetime = 0.0;
    if (!vehicleLifetimes.empty()) {
        simtime_t sum = 0;
        for (auto& lt : vehicleLifetimes) sum += lt;
        avgLifetime = sum.dbl() / vehicleLifetimes.size();
    }

    std::ofstream timeFile("avg_vehicle_lifetime.txt", std::ios::app);
    if (timeFile.is_open()) {
        timeFile
                 << avgLifetime << "\n";
        timeFile.close();
    } else {
        std::cerr << "Cannot open file avg_vehicle_lifetime.txt" << std::endl;
    }
}

void emergency::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void emergency::onWSM(BaseFrame1609_4* wsm) {

    // Cast the received message to our specific message type

    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string myType = traciVehicle->getVType();
    if(myType=="DEFAULT_VEHTYPE"&&receivedWSM->getvtype()==0)
    {
        return;
    }
    // If serial is not 0, it is a reply message; process collision warning logic
    if (receivedWSM->getmessagetype() == 1 && receivedWSM->getSerial() == myId) {

        //std::cout << "1111111111" << std::endl;
            //std::cout << receivedWSM->getSenderAddress() <<  std::endl;
            // Parse string containing distance data (e.g., semicolon-separated numbers)
            const char* demoDataCStr = receivedWSM->getdistancearray();
            std::string demoDataStr(demoDataCStr);
            std::vector<double> distances;
            std::istringstream dataStream(demoDataStr);
            std::string token;
            TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());

            // Get remote vehicle ID (SenderAddress was stored when sending)
            int remoteID = receivedWSM->getSenderAddress();
            int i = 0;
            while (std::getline(dataStream, token, ';')) {
                try {
                    double d = std::stod(token);
                    //std::cout << i <<":" <<d << std::endl;
                    i++;
                    distances.push_back(d);
                } catch (const std::exception& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
            double mySpeed = mobility->getSpeed();
            bool collisionRisk = checkDistancesCondition(distances).first;
            if (collisionRisk)
            {
                if(myType=="DEFAULT_VEHTYPE")
                {
                    TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
                    if(mySpeed > 3)
                    {
                        mySpeed= mySpeed - 3;
                    }
                    else
                    {
                        mySpeed = 0;
                    }
                    traciVehicle.slowDown(mySpeed, 1);
                    std::cout << "(" << mobility->getExternalId() << ")"<<myId<<" slowing down due to collision risk with remote vehicle "
                                                      << remoteID << "." << std::endl;
                }
                /*if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
                    collisionWarnings.insert(remoteID);
                    if (mySpeed > receivedWSM->getspeed()) {
                        decelerationResponsibles.insert(remoteID);
                    }
                }
                if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
                    TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
                    if(mySpeed > 2)
                    {
                        mySpeed= mySpeed - 2;
                    }
                    else
                    {
                        mySpeed = 0;
                    }
                    traciVehicle.slowDown(mySpeed, 1);
                    std::cout << "(" << mobility->getExternalId() << ")"<<myId<<" slowing down due to collision risk with remote vehicle "
                              << remoteID << "." << std::endl;
                }*/
            }
    }

    if (receivedWSM->getmessagetype() == 0) {
        simtime_t currentTime = simTime();

        const char* demoDataCStr = receivedWSM->getDemoData();
        std::string demoDataStr(demoDataCStr);

        // Parse point data containing x and y coordinates (assuming semicolon separator, comma between x,y)
        std::vector<double> x;
        std::vector<double> y;
        std::istringstream dataStream(demoDataStr);
        std::string pointStr;
        while (std::getline(dataStream, pointStr, ';')) {
            std::istringstream pointStream(pointStr);
            std::string xStr, yStr;
            if (std::getline(pointStream, xStr, ',') && std::getline(pointStream, yStr)) {
                try {
                    x.push_back(std::stod(xStr));
                    y.push_back(std::stod(yStr));
                } catch (const std::exception &e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
        }

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
        Coord currentPos = mobility->getPositionAt(simTime());

        std::vector<double> predictedX;
        std::vector<double> predictedY;
        predictedX.push_back(currentPos.x);
        predictedY.push_back(currentPos.y);


        std::string vehId = mobility->getExternalId();
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            double s = speed * t + 0.5 * acceleration * t * t;
            auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
            currentPos.x = newPosPair.first;
            currentPos.y = newPosPair.second;
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }
        std::vector<double> distances;
        for (size_t i = 0; i < fixBatchSize; ++i) {
            double dx = predictedX[i] - x[i];
            double dy = predictedY[i] - y[i];
            double distance = std::sqrt(dx * dx + dy * dy);
            distances.push_back(distance);
        }
        // Construct reply message and send out the predicted distance differences
        TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
        populateWSM(replyMsg);
        replyMsg->setSenderAddress(myId);
        replyMsg->setSerial(receivedWSM->getSenderAddress());
        // Send current vehicle speed as demoData

        std::ostringstream oss;
        for (size_t i = 0; i < distances.size(); ++i) {

            oss << distances[i];
            if (i != distances.size() - 1) {
                oss << ";";
            }
        }
        std::string distanceStr = oss.str();
        replyMsg->setdistancearray(distanceStr.c_str());
        replyMsg->setmessagetype(1);
        replyMsg->setspeed(mobility->getSpeed());
        if(myType =="ambulance")
        {
            replyMsg->setvtype(1);
        }
        sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");
    }
    /*if (receivedWSM->getmessagetype() == 2&&receivedWSM->getSerial() == myId)
    {
        TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
        Coord currentPos = mobility->getPositionAt(simTime());
        double dx = currentPos.x - receivedWSM->getx();
        double dy = currentPos.y - receivedWSM->gety();
        double distance = dx * dx + dy * dy;
        int remoteID = receivedWSM->getSenderAddress();
        if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
            collisionWarnings.insert(remoteID);
        if(distance > receivedWSM->getdistance())
        {
           decelerationResponsibles.insert(remoteID);
        }
        }
        if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
        double speed = mobility->getSpeed();
        if(speed > 2)
        {
            speed= speed - 2;
        }
        else
        {
            speed = 0;
        }
        traciVehicle.slowDown(speed, 1);
        std::cout << "(" << mobility->getExternalId() << ")"<<myId<<" slowing down due to collision risk with remote vehicle "
                << remoteID << "." << std::endl;
        }
        if (collisionRisk) {
            double a = mySpeed + checkDistancesCondition(distances).second*acceleration*0.1;
            double b = remoteSpeed+ checkDistancesCondition(distances).second*remoteacceleration*0.1;

            // If this is the first collision warning from this remote vehicle, determine responsibility based on initial speeds
            if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
                collisionWarnings.insert(remoteID);
                std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!first" << std::endl;
                std::cout << "(" << mobility->getExternalId()<<"speed"<< mySpeed<<"id"<<myId<<std::endl;
                for (int i = 0; i < 16; i++) {
                    std::cout << distances[i] << std::endl;
                }
                std::cout << a << std::endl;
                std::cout << acceleration << std::endl;
                std::cout << b << std::endl;
                std::cout << remoteacceleration << std::endl;

                std::cout <<checkDistancesCondition(distances).second<< std::endl;
                std::cout <<mySpeed<< std::endl;
                std::cout <<remoteSpeed<< std::endl;
                std::cout << simTime()<< std::endl;
                // If current vehicle speed is higher than the other, this vehicle is responsible for deceleration
                if (mySpeed > remoteSpeed) {
                    decelerationResponsibles.insert(remoteID);
                }
            }
            // If this vehicle is determined to be responsible for deceleration in this pair, execute deceleration
            if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
                TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
                // Deceleration logic can be adjusted here; example below reduces speed by 2 units
               //double newSpeed =(mySpeed * find(distances).first + 0.5 * acceleration * find(distances).first * find(distances).first)*2/find(distances).second -  mySpeed;
                //std::cout << acceleration<< std::endl;
                //std::cout << newSpeed<< std::endl;
                //if (newSpeed < 0)
                //    newSpeed = 0;
                //std::cout << find(distances).first<<find(distances).second<< std::endl;
                if(mySpeed > 3)
                {
                    mySpeed= mySpeed - 3;
                }
                else
                {
                    mySpeed = 0;
                }
                traciVehicle.slowDown(mySpeed, 1);
                if(mySpeed == 0)
                    decelerationResponsibles.erase(remoteID);
                std::cout << "(" << mobility->getExternalId() << ")"<<myId<<" slowing down due to collision risk with remote vehicle "
                          << remoteID << "." << std::endl;
            }
            else
            {
                //collisionWarnings.erase(remoteID);
                std::cout << "(Opponent "<<receivedWSM->getSenderAddress()<<" decelerating." << std::endl;
            }
         }
    }*/
}



void emergency::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void emergency::handleSelfMsg(cMessage* msg) {

    if (msg == sendMessageEvent) {

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
        Coord currentPos = mobility->getPositionAt(simTime());
        std::vector<double> predictedX;
        std::vector<double> predictedY;
        predictedX.push_back(currentPos.x);
        predictedY.push_back(currentPos.y);

        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            double s = speed * t + 0.5 * acceleration * t * t;
            auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
            currentPos.x = newPosPair.first;
            currentPos.y = newPosPair.second;
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }


        // Extract s and d components.
        std::ostringstream oss;
        for (size_t i = 0; i < predictedX.size(); ++i) {
            oss << predictedX[i] << "," << predictedY[i];
            if (i != predictedX.size() - 1) {
                oss << ";";
            }
        }

        std::string serializedData = oss.str();
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setSenderAddress(myId);
        newWSM->setDemoData(serializedData.c_str());
        newWSM->setmessagetype(0);
        std::string myType = traciVehicle->getVType();

        if(myType =="ambulance")
        {
            newWSM->setvtype(1);
        }
        sendDown(newWSM);

        //std::cout << "(" << myId << ") send at " << currentTime << std::endl;
        //scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}

void emergency::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
