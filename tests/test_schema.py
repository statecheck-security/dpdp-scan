import json
from pathlib import Path

from dpdp_scan.engine import scan_path
from dpdp_scan.masking import DECLARED
from dpdp_scan.model import Category, Confidence
from dpdp_scan.schema import classify_file, schema_kind
from dpdp_scan.schema.parsers import parse_prisma, parse_schema_document, parse_sql
from dpdp_scan.walker import WalkOptions

SQL = """
-- customers, with a comment that mentions aadhaar_no (not a column)
CREATE TABLE IF NOT EXISTS public."customers" (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name     TEXT NOT NULL,
    aadhar_no     CHAR(12),
    email         TEXT NOT NULL CHECK (email LIKE '%@%'),
    mob_no        VARCHAR(15),
    dob           DATE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT customers_email_key UNIQUE (email),
    FOREIGN KEY (id) REFERENCES other(id)
);

create table orders (
  order_id bigserial,
  amount numeric(12, 2),
  shipping_pincode text,
  primary key (order_id)
);

ALTER TABLE customers ADD COLUMN IF NOT EXISTS pan_number CHAR(10);
ALTER TABLE orders ADD CONSTRAINT orders_amount_check CHECK (amount > 0);
"""

PRISMA = """
generator client {
  provider = "prisma-client-js"
}

model User {
  id            String   @id @default(cuid())
  walletAddress String   @unique @db.VarChar(42)
  username      String?  @unique
  avatarUrl     String?
  createdAt     DateTime @default(now())
  // dob is not declared here
  refreshTokens RefreshToken[]

  @@index([username])
}

model RefreshToken {
  id        String @id
  tokenHash String @unique
  user      User   @relation(fields: [userId], references: [id])
  userId    String
}

enum Role {
  ADMIN
}
"""

OPENAPI_YAML = """
openapi: 3.0.3
info:
  title: KYC API
paths:
  /customers:
    post:
      parameters:
        - name: x-request-id
          in: header
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Customer'
components:
  schemas:
    Customer:
      type: object
      properties:
        id: { type: string }
        aadhaarNumber: { type: string }
        emailAddress: { type: string, format: email }
        dateOfBirth: { type: string, format: date }
        address:
          type: object
          properties:
            line1: { type: string }
            pincode: { type: string }
      example:
        aadhaarNumber: "999999990019"
"""

JSON_SCHEMA = json.dumps(
    {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Employee",
        "properties": {"employee_id": {}, "pan": {}, "salary": {}, "blood_group": {}},
    },
    indent=2,
)


def test_parse_sql_columns_tables_and_alter() -> None:
    fields = {(f.container, f.name): f.line for f in parse_sql(SQL)}
    assert ("customers", "aadhar_no") in fields
    assert ("customers", "pan_number") in fields  # ALTER TABLE ADD COLUMN
    assert ("orders", "shipping_pincode") in fields
    assert fields[("customers", "aadhar_no")] == 6
    names = {n for _, n in fields}
    assert "CONSTRAINT" not in names and "FOREIGN" not in names and "primary" not in names
    assert "orders_amount_check" not in names


def test_parse_prisma_models_and_lines() -> None:
    fields = {(f.container, f.name): f.line for f in parse_prisma(PRISMA)}
    assert ("User", "walletAddress") in fields
    assert ("RefreshToken", "tokenHash") in fields
    assert ("User", "index") not in fields and ("Role", "ADMIN") not in fields
    assert fields[("User", "walletAddress")] == 8


def test_parse_openapi_yaml_properties_and_parameters() -> None:
    fields = {f.name: f for f in parse_schema_document(OPENAPI_YAML)}
    assert "aadhaarNumber" in fields and "pincode" in fields and "x-request-id" in fields
    assert fields["aadhaarNumber"].container.endswith("components.schemas.Customer")
    assert fields["aadhaarNumber"].line == 22
    assert fields["pincode"].container.endswith("Customer.address")


def test_parse_json_schema() -> None:
    assert {f.name for f in parse_schema_document(JSON_SCHEMA)} == {
        "employee_id",
        "pan",
        "salary",
        "blood_group",
    }


def test_non_schema_json_and_yaml_yield_nothing() -> None:
    assert parse_schema_document('{"name": "pkg", "version": "1.0.0"}') == []
    assert parse_schema_document("key: value\nlist:\n  - a\n") == []
    assert parse_schema_document("not: [valid: yaml") == []


def test_schema_kind() -> None:
    assert schema_kind("db/migrations/001.sql") == "sql"
    assert schema_kind("prisma/schema.prisma") == "prisma"
    assert schema_kind("api/openapi.yaml") == "openapi"
    assert schema_kind("package.json") is None
    assert schema_kind("src/app.py") is None


def test_classify_file_sql_findings() -> None:
    findings = classify_file(SQL, "db/schema.sql")
    by_loc = {f.locator: f for f in findings}
    assert by_loc["customers.aadhar_no"].category == Category.IDENTITY
    assert by_loc["customers.aadhar_no"].confidence == Confidence.HIGH
    assert by_loc["customers.dob"].provisions[0].ref == "S.9"
    assert by_loc["orders.shipping_pincode"].category == Category.CONTACT
    assert all(f.evidence == DECLARED and f.detector_id == "schema_sql" for f in findings)
    assert "customers.created_at" not in by_loc and "orders.amount" not in by_loc


def test_classify_file_prisma_is_sensible_for_bytesnapp_shaped_schema() -> None:
    locs = {f.locator: f.confidence for f in classify_file(PRISMA, "schema.prisma")}
    assert locs == {
        "User.walletAddress": Confidence.LOW,
        "User.username": Confidence.LOW,
        "User.avatarUrl": Confidence.LOW,
    }


def test_scan_path_combines_values_and_declarations(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(SQL, encoding="utf-8")
    (tmp_path / "openapi.yaml").write_text(OPENAPI_YAML, encoding="utf-8")
    result = scan_path(tmp_path, walk_options=WalkOptions(use_git=False))
    inv = result.inventory
    # full_name, aadhar_no, email, mob_no, dob, shipping_pincode, pan_number
    assert inv.by_detector["schema_sql"] == 7
    # aadhaarNumber, emailAddress, dateOfBirth, address (the object), address.pincode
    assert inv.by_detector["schema_openapi"] == 5
    # The example value in the OpenAPI file is a UIDAI test UID: allowlisted, no value finding.
    assert "in_aadhaar" not in inv.by_detector
    dump = json.dumps(inv.to_dict())
    assert "999999990019" not in dump
    assert "customers.aadhar_no" in dump
