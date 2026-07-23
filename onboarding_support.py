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

ACTIVITY_OPTIONS = [
    ("road_cycling", "Road cycling"),
    ("gravel_cycling", "Gravel cycling"),
    ("mountain_biking", "Mountain biking"),
    ("indoor_cycling", "Indoor cycling"),
    ("running", "Running"),
    ("walking", "Walking"),
    ("strength_training", "Strength training"),
    ("cross_country_skiing", "Cross-country skiing"),
    ("other", "Other activity"),
]

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

def training_step_complete(training):
    return bool(
        training
        and isinstance(training.get("activity_preferences"), dict)
        and any((value or {}).get("priority", 0) > 0
                for value in training.get("activity_preferences", {}).values())
        and isinstance(training.get("weekday_minutes"), int)
        and isinstance(training.get("weekend_minutes"), int)
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
    integrations = integrations or {}
    completion = {
        "profile": profile_step_complete(profile),
        "training": training_step_complete(training),
        "context": context_step_complete(context),
        "goals": goals_step_complete(goals),
        "strava": bool(integrations.get("strava")),
        "withings": bool(integrations.get("withings")),
        "integrations": bool(integrations.get("ai")),
    }
    next_step = next(
        (step for step in ONBOARDING_STEPS if not completion[step["key"]]),
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
