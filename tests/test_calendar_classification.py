"""iCal calendar content is labeled `calendar`, not just `contacts`.

A calendar event read or exported as iCalendar lists attendee email addresses, which
previously tainted it only as `contacts` (the content classifier had no calendar
signal). It now also carries `calendar` — a clearer signal for the verifier's intent
check and the activity UI. Same policy class (personal_private), so gating is unchanged.
Casual prose must NOT pick up the `calendar` taint (no false positives).
"""

from __future__ import annotations

from support import *  # noqa: F403

_VEVENT = (
    "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:1:1 with Alex\n"
    "DTSTART:20260612T150000Z\nDTEND:20260612T153000Z\n"
    "ATTENDEE:mailto:alex@example.com\nEND:VEVENT\nEND:VCALENDAR"
)


def test_ical_event_is_labeled_calendar():
    plugin = load_plugin()
    classes = plugin._classes_from_content(_VEVENT)
    assert "calendar" in classes
    # It still trips `contacts` on the attendee address — both are personal_private.
    assert "contacts" in classes


def test_casual_prose_does_not_taint_calendar():
    plugin = load_plugin()
    for benign in (
        "Let's grab coffee, maybe a meeting at 3 tomorrow?",
        "The event was great and the schedule worked out.",
        "dtstart sounds like a variable name in this code",
    ):
        assert "calendar" not in plugin._classes_from_content(benign)


def test_calendar_label_does_not_change_gating():
    """Labeling adds `calendar`, which maps to the same egress-gating policy class as
    `contacts`, so the deterministic decision is unchanged."""
    plugin = load_plugin()
    only_contacts = plugin._egress_gating_policy_classes({"contacts"})
    with_calendar = plugin._egress_gating_policy_classes({"contacts", "calendar"})
    assert only_contacts == with_calendar == {"personal_private"}
