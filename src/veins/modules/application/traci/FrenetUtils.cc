#include "FrenetUtils.h"
#include <limits>
#include <cmath>

namespace veins {

static std::vector<Coord> buildReferenceLine() {
    std::vector<Coord> refLine;
    refLine.push_back({252.537, 394.488});
    refLine.push_back({209.193, 415.188});
    refLine.push_back({204.261, 417.543});
    refLine.push_back({198.766, 420.168});
    refLine.push_back({195.780, 421.347});
    refLine.push_back({193.948, 421.100});
    refLine.push_back({193.901, 421.058});
    refLine.push_back({193.807, 420.973});
    refLine.push_back({193.432, 420.635});
    refLine.push_back({193.197, 420.424});
    refLine.push_back({192.962, 420.212});
    refLine.push_back({192.677, 419.882});
    refLine.push_back({192.491, 419.551});
    refLine.push_back({191.651, 418.003});
    refLine.push_back({189.670, 413.329});
    return refLine;
}

Coord getCartesianFromFrenet(double s, double d) {
    std::vector<Coord> refLine = buildReferenceLine();
    double sAccum = 0.0;
    Coord refPoint = {0.0, 0.0};
    double theta = 0.0;

    for (size_t i = 0; i < refLine.size() - 1; i++) {
        Coord A = refLine[i];
        Coord B = refLine[i+1];
        double segLen = std::hypot(B.x - A.x, B.y - A.y);

        if (sAccum + segLen >= s) {
            double t = (s - sAccum) / segLen;
            refPoint.x = A.x + t * (B.x - A.x);
            refPoint.y = A.y + t * (B.y - A.y);
            theta = std::atan2(B.y - A.y, B.x - A.x);
            break;
        }
        sAccum += segLen;
    }

    Coord result;
    result.x = refPoint.x - d * std::sin(theta);
    result.y = refPoint.y + d * std::cos(theta);
    return result;
}

FrenetCoord getFrenetCoordinates(const Coord &pos) {
    std::vector<Coord> refLine = buildReferenceLine();
    double minDist = std::numeric_limits<double>::max();
    double sAtMin = 0.0;
    double dAtMin = 0.0;
    double sAccum = 0.0;

    for (size_t i = 0; i < refLine.size() - 1; i++) {
        Coord A = refLine[i];
        Coord B = refLine[i+1];
        double dx = B.x - A.x;
        double dy = B.y - A.y;
        double segLen = std::sqrt(dx * dx + dy * dy);

        double t = ((pos.x - A.x) * dx + (pos.y - A.y) * dy) / (segLen * segLen);
        if (t < 0) t = 0;
        if (t > 1) t = 1;

        double projX = A.x + t * dx;
        double projY = A.y + t * dy;
        double dist = std::hypot(pos.x - projX, pos.y - projY);

        if (dist < minDist) {
            minDist = dist;
            sAtMin = sAccum + t * segLen;
            double cross = dx * (pos.y - A.y) - dy * (pos.x - A.x);
            dAtMin = (cross >= 0 ? dist : -dist);
        }

        sAccum += segLen;
    }
    return { sAtMin, dAtMin };
}

} // namespace veins
