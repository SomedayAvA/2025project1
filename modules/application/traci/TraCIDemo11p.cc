//
// Copyright (C) 2006-2011 Christoph Sommer <christoph.sommer@uibk.ac.at>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "veins/modules/application/traci/TraCIDemo11p.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"

using namespace veins;

Define_Module(veins::TraCIDemo11p);



TraCIDemo11p::~TraCIDemo11p() {
    cancelAndDelete(sendMessageEvent);
}

void TraCIDemo11p::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        beaconInterval = par("beaconInterval");
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = -1;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + beaconInterval, sendMessageEvent);
    }
}

void TraCIDemo11p::onWSA(DemoServiceAdvertisment* wsa)
{

}

void TraCIDemo11p::onWSM(BaseFrame1609_4* frame)
{
    std::cout << "Car["  << std::endl;
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    std::string revWSM_str = wsm->getDemoData();

}

void TraCIDemo11p::handleSelfMsg(cMessage* msg)
{
    switch (msg->getKind()) {
    case SEND_BEACON_EVT: {
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        sendDown(newWSM);
        simtime_t jitter = uniform(-0.001, 0.001);
        simtime_t nextTime = simTime() + beaconInterval + jitter;
        scheduleAt(nextTime, sendMessageEvent);
        std::cout << this->myId << ": " << newWSM->getDemoData() << std::endl;
        break;
    }
    case SEND_WSA_EVT: {
        DemoServiceAdvertisment* wsa = new DemoServiceAdvertisment();
        populateWSM(wsa);
        sendDown(wsa);
        scheduleAt(simTime() + wsaInterval, sendWSAEvt);
        break;
    }
    default: {
        if (msg) EV_WARN << "APP: Error: Got Self Message of unknown kind! Name: " << msg->getName() << endl;
        break;
    }
    }

}

void TraCIDemo11p::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
