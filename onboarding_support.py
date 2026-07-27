from html import escape

ONBOARDING_STEPS = [
    {"key": "profile", "label": "Personal profile", "path": "/onboarding/profile"},
    {"key": "training", "label": "Training profile", "path": "/onboarding/training"},
    {"key": "context", "label": "Coaching context", "path": "/onboarding/context"},
    {"key": "goals", "label": "Goals", "path": "/onboarding/goals"},
    {"key": "strava", "label": "Connect Strava", "path": "/onboarding/strava"},
    {"key": "withings", "label": "Connect Withings", "path": "/onboarding/withings"},
    {"key": "integrations", "label": "AI integrations", "path": "/onboarding/integrations"},
]

COMMON_TIMEZONES = [
    "America/New_York", "America/Chicago", "America/Denver",
    "America/Phoenix", "America/Los_Angeles", "America/Anchorage",
    "Pacific/Honolulu", "America/Toronto", "America/Vancouver",
    "Europe/London", "Europe/Paris", "Asia/Tokyo", "Australia/Sydney",
]

# Values use Strava's SportType enumeration so stored preferences can be
# compared directly with retrieved activities. Labels are grouped in the UI.
ACTIVITY_GROUPS = [
    ("Cycling", [
        ("Ride", "Road or general cycling"),
        ("GravelRide", "Gravel cycling"),
        ("MountainBikeRide", "Mountain biking"),
        ("EBikeRide", "E-bike riding"),
        ("EMountainBikeRide", "E-mountain biking"),
        ("VirtualRide", "Indoor or virtual cycling"),
        ("Handcycle", "Handcycling"),
        ("Velomobile", "Velomobile"),
    ]),
    ("Running and walking", [
        ("Run", "Road or general running"),
        ("TrailRun", "Trail running"),
        ("VirtualRun", "Indoor or virtual running"),
        ("Walk", "Walking"),
        ("Hike", "Hiking"),
        ("Wheelchair", "Wheelchair activity"),
    ]),
    ("Strength, fitness, and rehabilitation", [
        ("WeightTraining", "Strength training"),
        ("Workout", "General workout"),
        ("Crossfit", "CrossFit"),
        ("HighIntensityIntervalTraining", "High-intensity interval training"),
        ("Elliptical", "Elliptical"),
        ("StairStepper", "Stair stepper"),
        ("Yoga", "Yoga"),
        ("Pilates", "Pilates"),
        ("Dance", "Dance"),
        ("PhysicalTherapy", "Physical therapy"),
    ]),
    ("Winter sports", [
        ("AlpineSki", "Alpine skiing"),
        ("BackcountrySki", "Backcountry skiing"),
        ("NordicSki", "Cross-country skiing"),
        ("RollerSki", "Roller skiing"),
        ("Snowboard", "Snowboarding"),
        ("Snowshoe", "Snowshoeing"),
        ("IceSkate", "Ice skating"),
    ]),
    ("Water sports", [
        ("Swim", "Swimming"),
        ("Rowing", "Rowing"),
        ("VirtualRow", "Indoor or virtual rowing"),
        ("Canoeing", "Canoeing"),
        ("Kayaking", "Kayaking"),
        ("StandUpPaddling", "Stand-up paddling"),
        ("Surfing", "Surfing"),
        ("Kitesurf", "Kitesurfing"),
        ("Windsurf", "Windsurfing"),
        ("Sail", "Sailing"),
    ]),
    ("Racquet and court sports", [
        ("Badminton", "Badminton"),
        ("Padel", "Padel"),
        ("Pickleball", "Pickleball"),
        ("Racquetball", "Racquetball"),
        ("Squash", "Squash"),
        ("TableTennis", "Table tennis"),
        ("Tennis", "Tennis"),
    ]),
    ("Team and field sports", [
        ("Basketball", "Basketball"),
        ("Cricket", "Cricket"),
        ("Soccer", "Soccer"),
        ("Volleyball", "Volleyball"),
    ]),
    ("Outdoor and other sports", [
        ("Golf", "Golf"),
        ("RockClimbing", "Rock climbing"),
        ("InlineSkate", "Inline skating"),
        ("Skateboard", "Skateboarding"),
    ]),
]

ACTIVITY_OPTIONS = [
    activity
    for _group_label, activities in ACTIVITY_GROUPS
    for activity in activities
]

# Profiles saved before Step 19 used application-specific keys. They are
# translated when the user next edits the training profile.
LEGACY_ACTIVITY_ALIASES = {
    "road_cycling": "Ride",
    "gravel_cycling": "GravelRide",
    "mountain_biking": "MountainBikeRide",
    "indoor_cycling": "VirtualRide",
    "running": "Run",
    "walking": "Walk",
    "strength_training": "WeightTraining",
    "cross_country_skiing": "NordicSki",
    "other": "Workout",
}

ACTIVITY_FREQUENCY_OPTIONS = [
    ("never", "Rarely or never"),
    ("monthly", "A few times per month"),
    ("weekly", "About weekly"),
    ("several_weekly", "Several times per week"),
    ("most_days", "Most days"),
]

GOAL_STATUS_OPTIONS = [
    ("active", "Active"),
    ("planned", "Planned"),
    ("maintenance", "Ongoing / maintenance"),
]
GOAL_PRIORITY_OPTIONS = [
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
]
MAX_GOALS = 5

COACHING_STYLE_OPTIONS = [
    ("adaptive", "Adaptive — adjust recommendations to readiness and circumstances"),
    ("analytical", "Analytical — emphasize data, rationale, and trends"),
    ("direct", "Direct — concise recommendations with minimal cushioning"),
    ("encouraging", "Encouraging — supportive framing and reinforcement"),
]

EQUIPMENT_OPTIONS = [
    ("smart_trainer", "Smart trainer"),
    ("power_meter", "Bike power meter"),
    ("heart_rate_monitor", "Heart-rate monitor"),
    ("gps_watch", "GPS watch"),
    ("gym_access", "Gym access"),
    ("treadmill", "Treadmill"),
    ("rowing_machine", "Rowing machine"),
]

PLATFORM_OPTIONS = [
    ("zwift", "Zwift"), ("trainerroad", "TrainerRoad"),
    ("wahoo_systm", "Wahoo SYSTM"), ("peloton", "Peloton"),
    ("rouvy", "Rouvy"),
]

def profile_step_complete(profile):
    return bool(
        profile
        and profile.get("display_name")
        and profile.get("timezone")
        and profile.get("units") in {"imperial", "metric"}
        and profile.get("date_of_birth")
        and profile.get("height_value")
        and profile.get("weather_location")
    )

def _positive_priority(value):
    try:
        return int((value or {}).get("priority") or 0) > 0
    except (TypeError, ValueError, AttributeError):
        return False


def _integer_like(value):
    try:
        int(value)
        return value is not None and str(value).strip() != ""
    except (TypeError, ValueError):
        return False


def training_step_complete(training):
    preferences = (
        training.get("activity_preferences")
        if isinstance(training, dict)
        else None
    )
    return bool(
        isinstance(training, dict)
        and isinstance(preferences, dict)
        and any(_positive_priority(value) for value in preferences.values())
        and _integer_like(training.get("weekday_minutes"))
        and _integer_like(training.get("weekend_minutes"))
        and training.get("coaching_style")
        and training.get("bad_weather_strategy")
    )

def context_step_complete(context):
    return bool(
        context and any(
            (context.get(field) or "").strip()
            for field in (
                "coaching_preferences", "training_philosophy",
                "lifestyle_constraints", "additional_context",
            )
        )
    )

def goals_step_complete(goals):
    return any(
        goal.get("title")
        and goal.get("status") in {"active", "planned", "maintenance"}
        for goal in (goals or [])
    )

def onboarding_state(profile, training, context=None, goals=None, integrations=None):
    integration_state = integrations if isinstance(integrations, dict) else {}

    strava_complete = bool(integration_state.get("strava"))
    withings_complete = bool(
        integration_state.get("withings")
        or integration_state.get("withings_skipped")
    )
    ai_complete = bool(integration_state.get("ai"))

    completion = {
        "profile": profile_step_complete(profile),
        "training": training_step_complete(training),
        "context": context_step_complete(context),
        "goals": goals_step_complete(goals),
        "strava": strava_complete,
        "withings": withings_complete,
        "integrations": ai_complete,
    }
    next_step = next(
        (step for step in ONBOARDING_STEPS if not completion.get(step["key"], False)),
        None,
    )
    return {"completion": completion, "next_step": next_step, "complete": next_step is None}

def onboarding_progress_html(state, current_key=None):
    editable = {"profile", "training", "context", "goals"}
    items = []
    for step in ONBOARDING_STEPS:
        key = step["key"]
        if state["completion"].get(key):
            status, css_class = "✓", "complete"
        elif key == current_key:
            status, css_class = "→", "current"
        else:
            status, css_class = "", "pending"
        if key in editable or state["completion"].get(key):
            content = (
                f'<a href="{escape(step["path"])}">'
                f'<span>{escape(step["label"])}</span><strong>{status}</strong></a>'
            )
        else:
            content = (
                '<div class="wizard-step-disabled">'
                f'<span>{escape(step["label"])}</span><strong>{status}</strong></div>'
            )
        items.append(f'<li class="{css_class}">{content}</li>')
    return '<ol class="wizard-progress">' + "".join(items) + "</ol>"
