// curve_utils.cc
#include "curve_utils.h"

int globalInitFlag = 0;
const int fixBatchSize = 16;
int p = 1;
std::vector<Coord> curvePoints = {
    {330.906, 984.472},
    {330.004, 984.434},
    {329.135, 984.537},
    {328.311, 984.635},
    {328.311, 984.635},
    {326.837, 985.252},
    {326.837, 985.252},
    {325.462, 986.136},
    {325.462, 986.136},
    {324.834, 986.645},
    {324.309, 987.276},
    {323.79, 987.902},
    {322.819, 989.211},
    {322.819, 989.211},
    {322.225, 990.743},
    {321.927, 991.513},
    {321.732, 992.311}
};
std::vector<Coord> curvePoints1 = {
        {316.891, 984.819},
        {317.791, 985.013},
        {318.667, 985.29},
        {319.486, 985.624},
        {320.229, 985.988},
        {320.762, 986.576},
        {321.264, 987.131},
        {321.536, 987.783},
        {321.733, 988.476},
        {321.929, 989.166},
        {321.918, 989.873},
        {321.845, 991.299}
};

//----------------------------------------------------------------------------
// Helper: Compute new position using kinematics
//----------------------------------------------------------------------------
double distanceBetween(const Coord& a, const Coord& b) {
    return sqrt((a.x - b.x)*(a.x - b.x) + (a.y - b.y)*(a.y - b.y));
}

// Linear prediction function (Fallback)
std::pair<double, double> computeNewPosition(double x, double y,
                                             double speed,
                                             double acceleration,
                                             double angleDeg,
                                             double t) {
    // Convert angle to radians
    double angleRad = angleDeg * M_PI / 180.0;

    // If acceleration is too large, treat as constant speed
    if (acceleration > 100)
        acceleration = 0;

    // If decelerating, calculate the time required to stop
    double t_eff = t;
    if (acceleration < 0) {
        double t_stop = speed / (-acceleration);       // v0 / |a|
        if (t > t_stop)
            t_eff = t_stop;                            // Do not continue accumulating after stopping time
    }

    // Calculate displacement using effective time
    double displacement = speed * t_eff + 0.5 * acceleration * t_eff * t_eff;

    // Project onto x, y directions
    double deltaX = displacement * std::sin(angleRad);
    double deltaY = -displacement * std::cos(angleRad);

    return std::make_pair(x + deltaX, y + deltaY);
}

// Interpolate on the curve: given target cumulative distance, return corresponding coordinates
Coord interpolateOnCurve(const std::vector<Coord>& curve, double targetDistance, const std::vector<double>& cumDistances) {
    if (targetDistance >= cumDistances.back())
        return curve.back();
    for (size_t i = 0; i < cumDistances.size() - 1; ++i) {
        if (targetDistance >= cumDistances[i] && targetDistance < cumDistances[i+1]) {
            double segmentLen = cumDistances[i+1] - cumDistances[i];
            double ratio = (targetDistance - cumDistances[i]) / segmentLen;
            double newX = curve[i].x + ratio * (curve[i+1].x - curve[i].x);
            double newY = curve[i].y + ratio * (curve[i+1].y - curve[i].y);
            return {newX, newY};
        }
    }
    return curve.back();
}

// Project point p onto the curve, return the cumulative distance of the projection point on the curve
double projectOntoCurve(const std::vector<Coord>& curve, const std::vector<double>& cumDistances, const Coord& p) {
    double bestDistance = std::numeric_limits<double>::max();
    double bestProjection = 0.0;
    for (size_t i = 0; i < curve.size() - 1; ++i) {
        Coord A = curve[i];
        Coord B = curve[i+1];
        double ABx = B.x - A.x;
        double ABy = B.y - A.y;
        double AB2 = ABx * ABx + ABy * ABy;
        if (AB2 < 1e-6)
            continue;
        double APx = p.x - A.x;
        double APy = p.y - A.y;
        double t = (APx * ABx + APy * ABy) / AB2;
        if (t < 0) t = 0;
        if (t > 1) t = 1;
        double projX = A.x + t * ABx;
        double projY = A.y + t * ABy;
        double d = sqrt((p.x - projX)*(p.x - projX) + (p.y - projY)*(p.y - projY));
        if (d < bestDistance) {
            bestDistance = d;
            bestProjection = cumDistances[i] + t * sqrt(ABx * ABx + ABy * ABy);
        }
    }
    return bestProjection;
}

//----------------------------------------------------------------------------
// Helper: Check distance condition
//----------------------------------------------------------------------------
std::pair<bool, int> checkDistancesCondition(const std::vector<double>& distances) {
    if (distances.empty()) {
        return { false, -1 };
    }

    // Check if the array is strictly increasing
    bool isAscending = true;
    for (size_t i = 1; i < distances.size(); ++i) {
        if (distances[i] <= distances[i - 1]) {
            isAscending = false;
            break;
        }
    }
    if (isAscending)
        return { false, -1 };

    // Find the index of the minimum value
    int minIndex = 0;
    double minValue = distances[0];
    for (size_t i = 1; i < distances.size(); ++i) {
        if (distances[i] < minValue) {
            minValue = distances[i];
            minIndex = i;
        }
    }
    // If minimum value is not less than threshold (3), return false, but still return the min index
    if (minValue >= 3)
        return { false, minIndex };

    return { true, minIndex };
}

std::pair<double, double> find(const std::vector<double>& distances) {
    if (distances.empty()) return {-1, -1};

    // Find the end position of the decreasing interval (index of the last element in the decreasing interval)
    int dec_end = 0;
    while (dec_end + 1 < distances.size() && distances[dec_end] > distances[dec_end + 1]) {
        dec_end++;
    }

    // Find the index of the first number greater than 7.5 within the decreasing interval, searching backwards
    int minIndexGreaterThan75 = -1;
    for (int i = dec_end; i >= 0; --i) {
        if (distances[i] > 7.5) {
            minIndexGreaterThan75 = i;
            break;
        }
    }
    if (minIndexGreaterThan75 == -1 && dec_end == 0) {
        return {0.0, 0.2};
    }

    // If no number greater than 7.5 exists, return default values
    if (minIndexGreaterThan75 == -1) {
        return {0.2, dec_end / 5.0};
    }
    if (dec_end == 0) {
        return {minIndexGreaterThan75 / 5.0, 0.2};
    }

    return {minIndexGreaterThan75 / 5.0, dec_end / 5.0};
}
