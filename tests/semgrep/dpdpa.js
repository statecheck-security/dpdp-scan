// Semgrep --test fixture for src/dpdp_scan/rules/dpdpa.yml (JS/TS rules).
// "ruleid:" marks a line the rule must flag, "ok:" a line it must not.
// Every identifier here is a field name; no values.
const logger = require("pino")();

function notify(user, order) {
  // ruleid: pii-in-logs-js
  console.log("welcome", user.email);
  // ruleid: pii-in-logs-js
  logger.info({ phone: user.mobileNo }, "otp sent");
  // ruleid: pii-in-logs-js
  console.error(`kyc failed for ${user.aadhaar}`);
  // ok: pii-in-logs-js
  console.log("order shipped", order.id);
  // ok: pii-in-logs-js
  logger.warn("retrying", { attempt: 3 });
}

function track(user) {
  // ruleid: pii-to-analytics-js
  analytics.track("Signed Up", { email: user.email });
  // ruleid: pii-to-analytics-js
  mixpanel.people.set({ $phone: user.phone });
  // ruleid: pii-to-analytics-js
  gtag("event", "signup", { user_email: user.email });
  // ruleid: pii-to-analytics-js
  dataLayer.push({ event: "lead", pan_number: form.panNumber });
  // ruleid: pii-to-analytics-js
  Sentry.setUser({ email: user.email });
  // ok: pii-to-analytics-js
  analytics.track("Signed Up", { plan: user.plan });
  // ok: pii-to-analytics-js
  gtag("event", "purchase", { value: order.total });
}

function register(req, res) {
  // ruleid: dob-without-age-gate-js
  const dob = req.body.dateOfBirth;
  // ruleid: dob-without-age-gate-js
  const birth = req.query["dob"];
  return res.json({ dob, birth });
}

function registerGated(req, res) {
  const dob = req.body.dateOfBirth;
  const age = yearsSince(dob);
  // ok: dob-without-age-gate-js
  if (age < 18) {
    return res.status(403).end();
  }
  return res.json({ dob });
}

function registerVerified(req, res) {
  // ok: dob-without-age-gate-js
  const dob = req.body.birthDate;
  verifyAge(dob);
  return res.json({ dob });
}

function unrelated(req, res) {
  // ok: dob-without-age-gate-js
  const city = req.body.city;
  return res.json({ city });
}

// Arrow handlers with two parameters, gated: the rule must stay quiet.
app.post("/signup-gated", (req, res) => {
  const dob = req.body.dateOfBirth;
  const age = yearsSince(dob);
  // ok: dob-without-age-gate-js
  if (age < 18) {
    return res.status(403).end();
  }
  return res.json({ dob });
});

app.post("/signup-verified", (req, res) => {
  // ok: dob-without-age-gate-js
  const dob = req.body.birthDate;
  verifyAge(dob);
  return res.json({ dob });
});

app.post("/signup-open", (req, res) => {
  // ruleid: dob-without-age-gate-js
  const dob = req.body.dateOfBirth;
  return res.json({ dob });
});
