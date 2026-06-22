# training_zones.py

CYCLING_FTP_WATTS = 245  # Update this manually when your FTP changes


def get_cycling_power_zones(ftp_watts=CYCLING_FTP_WATTS):
    """
    FTP-based cycling power zones.

    Zone model:
    Z1: Active recovery
    Z2: Endurance
    Z3: Tempo
    Z4: Threshold
    Z5: VO2 max
    Z6: Anaerobic
    Z7: Neuromuscular / sprint
    """
    return [
        {"zone": "z1", "name": "active_recovery", "min": 0, "max": 0.55 * ftp_watts},
        {"zone": "z2", "name": "endurance", "min": 0.55 * ftp_watts, "max": 0.75 * ftp_watts},
        {"zone": "z3", "name": "tempo", "min": 0.75 * ftp_watts, "max": 0.90 * ftp_watts},
        {"zone": "z4", "name": "threshold", "min": 0.90 * ftp_watts, "max": 1.05 * ftp_watts},
        {"zone": "z5", "name": "vo2_max", "min": 1.05 * ftp_watts, "max": 1.20 * ftp_watts},
        {"zone": "z6", "name": "anaerobic", "min": 1.20 * ftp_watts, "max": 1.50 * ftp_watts},
        {"zone": "z7", "name": "neuromuscular", "min": 1.50 * ftp_watts, "max": None},
    ]

def classify_power_watts(watts, ftp_watts=CYCLING_FTP_WATTS):
    """
    Classifies a watt value into an FTP-based zone.
    """
    for zone in get_cycling_power_zones(ftp_watts):
        zone_min = zone["min"]
        zone_max = zone["max"]

        if zone_max is None:
            if watts >= zone_min:
                return zone

        elif zone_min <= watts < zone_max:
            return zone

    return None

def power_zone_to_intensity(zone_name):
    """
    Converts FTP-based power zones into coaching intensity buckets.
    """
    if zone_name in ["z1", "z2"]:
        return "easy"

    if zone_name == "z3":
        return "moderate"

    if zone_name in ["z4", "z5", "z6", "z7"]:
        return "hard"

    return "unknown"

def summarize_power_stream_intensity(streams_payload, ftp_watts=CYCLING_FTP_WATTS):
    """
    Converts Strava watts/time/moving streams into easy/moderate/hard minutes
    using FTP-based power zones.

    This is better than Strava's activity power buckets because it classifies
    each stream point by actual watts.
    """
    result = {
        "easy_minutes": 0,
        "moderate_minutes": 0,
        "hard_minutes": 0,
        "source": "ftp_based_power_streams",
        "ftp_watts": ftp_watts,
        "has_power_stream": False,
        "details": {
            "easy_seconds": 0,
            "moderate_seconds": 0,
            "hard_seconds": 0,
            "unclassified_seconds": 0,
        }
    }

    time_data = streams_payload.get("time", {}).get("data", []) if streams_payload else []
    watts_data = streams_payload.get("watts", {}).get("data", []) if streams_payload else []
    moving_data = streams_payload.get("moving", {}).get("data", []) if streams_payload else []

    if not time_data or not watts_data:
        return result

    result["has_power_stream"] = True

    count = min(len(time_data), len(watts_data))
    if moving_data:
        count = min(count, len(moving_data))

    for i in range(count - 1):
        watts = watts_data[i]
        moving = moving_data[i] if moving_data else True

        if not moving or watts is None:
            continue

        seconds = max(0, time_data[i + 1] - time_data[i])

        ftp_zone = classify_power_watts(watts, ftp_watts)
        if not ftp_zone:
            result["details"]["unclassified_seconds"] += seconds
            continue

        intensity = power_zone_to_intensity(ftp_zone["zone"])

        if intensity == "easy":
            result["details"]["easy_seconds"] += seconds
        elif intensity == "moderate":
            result["details"]["moderate_seconds"] += seconds
        elif intensity == "hard":
            result["details"]["hard_seconds"] += seconds
        else:
            result["details"]["unclassified_seconds"] += seconds

    result["easy_minutes"] = round(result["details"]["easy_seconds"] / 60, 1)
    result["moderate_minutes"] = round(result["details"]["moderate_seconds"] / 60, 1)
    result["hard_minutes"] = round(result["details"]["hard_seconds"] / 60, 1)

    return result