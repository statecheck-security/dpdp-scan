# Semgrep --test fixture for src/dpdp_scan/rules/dpdpa.yml (Python rules).
# "ruleid:" marks a line the rule must flag, "ok:" a line it must not.
# Every identifier here is a field name; no values.
import logging

import analytics
import mixpanel
import sentry_sdk

logger = logging.getLogger(__name__)
log = logger


def notify(user, order):
    # ruleid: pii-in-logs-python
    logger.info("welcome %s", user.email)
    # ruleid: pii-in-logs-python
    logging.warning("otp sent to %s", user.phone)
    # ruleid: pii-in-logs-python
    log.debug(f"kyc for {user.aadhaar_no}")
    # ruleid: pii-in-logs-python
    print("pan", pan_number)
    # ok: pii-in-logs-python
    logger.info("order %s shipped", order.id)
    # ok: pii-in-logs-python
    logger.info("user %s logged in", user.id)
    # ok: pii-in-logs-python
    logging.error("payment failed for order %s", order.ref)


def track(user):
    # ruleid: pii-to-analytics-python
    analytics.track(user.id, "Signed Up", {"email": user.email})
    # ruleid: pii-to-analytics-python
    mixpanel.people.set(user.id, {"phone": user.mobile})
    # ruleid: pii-to-analytics-python
    sentry_sdk.set_user({"email": user.email, "id": user.id})
    # ok: pii-to-analytics-python
    analytics.track(user.id, "Signed Up", {"plan": user.plan})
    # ok: pii-to-analytics-python
    mixpanel.track(user.id, "Purchase", {"amount": order_total})


def register(request):
    # ruleid: dob-without-age-gate-python
    dob = request.data["dob"]
    # ruleid: dob-without-age-gate-python
    birth = request.POST.get("date_of_birth")
    return dob, birth


def register_gated(request):
    dob = request.data["dob"]
    age = years_since(dob)
    # ok: dob-without-age-gate-python
    if age < 18:
        return reject()
    return dob


def register_verified(request):
    # ok: dob-without-age-gate-python
    dob = request.form["birth_date"]
    verify_age(dob)
    return dob


def unrelated(request):
    # ok: dob-without-age-gate-python
    city = request.data["city"]
    return city
