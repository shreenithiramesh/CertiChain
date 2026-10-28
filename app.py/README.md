import streamlit as st
import sqlite3
import hashlib
import json
import qrcode
import pandas as pd
import io
import os

from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature



st.set_page_config(
    page_title="CertiChain",
    page_icon="🎓",
    layout="wide"
)

DATA_DIR = "data"
DB_PATH = os.path.join(DATA_DIR, "certichain.db")
PRIVATE_KEY_PATH = os.path.join(DATA_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(DATA_DIR, "public_key.pem")

os.makedirs(DATA_DIR, exist_ok=True)




def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_id TEXT PRIMARY KEY,
                student_name TEXT NOT NULL,
                register_no TEXT NOT NULL,
                degree TEXT NOT NULL,
                department TEXT NOT NULL,
                passing_year INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                cert_id TEXT NOT NULL,
                details TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
        """)


def load_or_create_keys():
    if not os.path.exists(PRIVATE_KEY_PATH):
        private_key = Ed25519PrivateKey.generate()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_bytes)

        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_bytes)

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None
        )

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key




def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")




def append_audit(action, cert_id, details):
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        previous = conn.execute("""
            SELECT event_hash FROM audit_log
            ORDER BY event_id DESC LIMIT 1
        """).fetchone()

        previous_hash = previous[0] if previous else "GENESIS"

        event = {
            "timestamp": timestamp,
            "action": action,
            "cert_id": cert_id,
            "details": details,
            "previous_hash": previous_hash
        }

        event_hash = sha256_bytes(canonical_json(event))

        conn.execute("""
            INSERT INTO audit_log
            (timestamp, action, cert_id, details,
             previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp, action, cert_id, details,
            previous_hash, event_hash
        ))


def verify_audit_chain():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT timestamp, action, cert_id, details,
                   previous_hash, event_hash
            FROM audit_log ORDER BY event_id
        """).fetchall()

    expected_previous = "GENESIS"

    for row in rows:
        timestamp, action, cert_id, details, previous_hash, event_hash = row

        if previous_hash != expected_previous:
            return False

        event = {
            "timestamp": timestamp,
            "action": action,
            "cert_id": cert_id,
            "details": details,
            "previous_hash": previous_hash
        }

        if sha256_bytes(canonical_json(event)) != event_hash:
            return False

        expected_previous = event_hash

    return True



def calculate_merkle_root(hashes):
    if not hashes:
        return None

    level = list(hashes)

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []

        for i in range(0, len(level), 2):
            combined = (level[i] + level[i + 1]).encode("utf-8")
            next_level.append(sha256_bytes(combined))

        level = next_level

    return level[0]



def issue_certificate(
    cert_id, student_name, register_no, degree,
    department, passing_year, issuer, file_bytes
):
    file_hash = sha256_bytes(file_bytes)

    payload = {
        "cert_id": cert_id,
        "student_name": student_name,
        "register_no": register_no,
        "degree": degree,
        "department": department,
        "passing_year": passing_year,
        "issuer": issuer,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "file_hash": file_hash
    }

    signature = private_key.sign(canonical_json(payload)).hex()

    try:
        with get_connection() as conn:
            conn.execute("""
                INSERT INTO certificates
                (cert_id, student_name, register_no, degree,
                 department, passing_year, issuer, issued_at,
                 file_hash, signature, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VALID')
            """, (
                payload["cert_id"],
                payload["student_name"],
                payload["register_no"],
                payload["degree"],
                payload["department"],
                payload["passing_year"],
                payload["issuer"],
                payload["issued_at"],
                payload["file_hash"],
                signature
            ))
    except sqlite3.IntegrityError:
        raise ValueError("Certificate ID already exists.")

    append_audit("ISSUE", cert_id, file_hash)

    signed_record = {
        "payload": payload,
        "signature": signature,
        "signature_algorithm": "Ed25519",
        "hash_algorithm": "SHA-256"
    }

    return signed_record




def verify_certificate(cert_id, uploaded_file_bytes):
    with get_connection() as conn:
        row = conn.execute("""
            SELECT cert_id, student_name, register_no, degree,
                   department, passing_year, issuer, issued_at,
                   file_hash, signature, status
            FROM certificates WHERE cert_id = ?
        """, (cert_id,)).fetchone()

    if not row:
        return False, "Certificate ID not found.", None

    columns = [
        "cert_id", "student_name", "register_no", "degree",
        "department", "passing_year", "issuer", "issued_at",
        "file_hash", "signature", "status"
    ]
    record = dict(zip(columns, row))

    if record["status"] != "VALID":
        return False, "Certificate is REVOKED.", record

    actual_hash = sha256_bytes(uploaded_file_bytes)

    if actual_hash != record["file_hash"]:
        return False, "File hash mismatch: file may have been altered.", record

    payload = {
        key: record[key]
        for key in [
            "cert_id", "student_name", "register_no", "degree",
            "department", "passing_year", "issuer", "issued_at",
            "file_hash"
        ]
    }

    try:
        public_key.verify(
            bytes.fromhex(record["signature"]),
            canonical_json(payload)
        )
    except (InvalidSignature, ValueError):
        return False, "Digital signature verification failed.", record

    return True, "Certificate verified successfully.", record




initialize_database()
private_key, public_key = load_or_create_keys()




st.title("🎓 CertiChain")
st.caption(
    "Offline Academic Certificate Verification "
    "| Digital Signatures | QR | Revocation | Audit Integrity"
)

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Issue Certificate",
        "Verify Certificate",
        "Revoke Certificate",
        "Integrity & Audit"
    ]
)




if page == "Dashboard":
    with get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM certificates"
        ).fetchone()[0]

        valid = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE status='VALID'"
        ).fetchone()[0]

        revoked = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE status='REVOKED'"
        ).fetchone()[0]

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Certificates", total)
    col2.metric("Valid Certificates", valid)
    col3.metric("Revoked Certificates", revoked)

    st.info(
        "This prototype stores its registry locally. "
        "No internet is required after the Python packages "
        "have been installed."
    )

    st.markdown("""
    **Key features**
    - SHA-256 certificate file fingerprint
    - Ed25519 digital signatures
    - QR code-based certificate ID
    - Certificate revocation tracking
    - Tamper-evident hash-chained audit log
    - Merkle root for a batch of certificate hashes
    """)




elif page == "Issue Certificate":
    st.subheader("Issue a New Certificate")

    with st.form("issue_form"):
        cert_id = st.text_input("Unique Certificate ID")
        student_name = st.text_input("Student Name")
        register_no = st.text_input("Register Number")
        degree = st.text_input("Degree")
        department = st.text_input("Department")
        passing_year = st.number_input(
            "Passing Year", min_value=1950,
            max_value=2100, value=2026
        )
        issuer = st.text_input("Issuing Institution")
        certificate_file = st.file_uploader(
            "Upload Original Certificate",
            type=["pdf", "png", "jpg", "jpeg"]
        )

        submitted = st.form_submit_button("Issue Certificate")

    if submitted:
        if not all([
            cert_id.strip(), student_name.strip(),
            register_no.strip(), degree.strip(),
            department.strip(), issuer.strip(),
            certificate_file
        ]):
            st.error("Please fill in all fields and upload a file.")
        else:
            try:
                signed_record = issue_certificate(
                    cert_id.strip(),
                    student_name.strip(),
                    register_no.strip(),
                    degree.strip(),
                    department.strip(),
                    int(passing_year),
                    issuer.strip(),
                    certificate_file.getvalue()
                )

                qr = qrcode.make("CERTICHAIN:" + cert_id.strip())
                qr_buffer = io.BytesIO()
                qr.save(qr_buffer, format="PNG")

                st.success("Certificate record created successfully.")
                st.image(qr_buffer.getvalue(), caption="Certificate QR Code")

                st.download_button(
                    "Download QR Code",
                    data=qr_buffer.getvalue(),
                    file_name=f"{cert_id}_qr.png",
                    mime="image/png"
                )

                st.download_button(
                    "Download Signed Record (JSON)",
                    data=json.dumps(
                        signed_record, indent=2, ensure_ascii=False
                    ).encode("utf-8"),
                    file_name=f"{cert_id}_record.json",
                    mime="application/json"
                )

            except ValueError as error:
                st.error(str(error))




elif page == "Verify Certificate":
    st.subheader("Verify Academic Certificate")

    cert_id = st.text_input("Enter Certificate ID")
    uploaded = st.file_uploader(
        "Upload the certificate file to verify",
        type=["pdf", "png", "jpg", "jpeg"],
        key="verify_file"
    )

    if st.button("Verify Certificate"):
        if not cert_id.strip() or uploaded is None:
            st.warning("Enter the ID and upload the certificate file.")
        else:
            success, message, record = verify_certificate(
                cert_id.strip(), uploaded.getvalue()
            )

            if success:
                st.success(message)
                st.json({
                    "Certificate ID": record["cert_id"],
                    "Student": record["student_name"],
                    "Degree": record["degree"],
                    "Department": record["department"],
                    "Passing Year": record["passing_year"],
                    "Institution": record["issuer"],
                    "Status": record["status"]
                })
            else:
                st.error(message)
                if record:
                    st.write("Recorded status:", record["status"])



elif page == "Revoke Certificate":
    st.subheader("Revoke a Certificate")

    st.warning(
        "Prototype mode: this page has no login or role-based access. "
        "Use only test data until authorization is implemented."
    )

    cert_id = st.text_input("Certificate ID to revoke")
    reason = st.text_area("Reason for revocation")

    if st.button("Revoke Certificate"):
        if not cert_id.strip() or not reason.strip():
            st.error("Enter both the certificate ID and reason.")
        else:
            with get_connection() as conn:
                row = conn.execute(
                    "SELECT status FROM certificates WHERE cert_id=?",
                    (cert_id.strip(),)
                ).fetchone()

                if row is None:
                    st.error("Certificate not found.")
                elif row[0] == "REVOKED":
                    st.warning("Certificate is already revoked.")
                else:
                    conn.execute("""
                        UPDATE certificates SET status='REVOKED'
                        WHERE cert_id=?
                    """, (cert_id.strip(),))

                    append_audit(
                        "REVOKE", cert_id.strip(), reason.strip()
                    )
                    st.success("Certificate marked as REVOKED.")




elif page == "Integrity & Audit":
    st.subheader("System Integrity")

    chain_ok = verify_audit_chain()

    if chain_ok:
        st.success("Audit hash chain is internally consistent.")
    else:
        st.error("Audit log integrity check failed.")

    with get_connection() as conn:
        rows = conn.execute("""
            SELECT cert_id, student_name, degree, department,
                   passing_year, file_hash, status
            FROM certificates ORDER BY issued_at DESC
        """).fetchall()

        audit_rows = conn.execute("""
            SELECT event_id, timestamp, action, cert_id,
                   details, previous_hash, event_hash
            FROM audit_log ORDER BY event_id
        """).fetchall()

    if rows:
        df = pd.DataFrame(rows, columns=[
            "Certificate ID", "Student", "Degree", "Department",
            "Passing Year", "SHA-256", "Status"
        ])

        st.markdown("### Certificate Registry")
        st.dataframe(df, use_container_width=True)

        merkle_root = calculate_merkle_root(
            [row[5] for row in rows]
        )

        st.markdown("### Certificate Batch Merkle Root")
        st.code(merkle_root or "No certificates")

        st.download_button(
            "Export Registry CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="certichain_registry.csv",
            mime="text/csv"
        )
    else:
        st.info("No certificates have been issued yet.")

    if audit_rows:
        audit_df = pd.DataFrame(audit_rows, columns=[
            "Event ID", "Timestamp", "Action", "Certificate ID",
            "Details", "Previous Hash", "Event Hash"
        ])

        st.markdown("### Audit History")
        st.dataframe(audit_df, use_container_width=True)

        st.download_button(
            "Export Audit CSV",
            data=audit_df.to_csv(index=False).encode("utf-8"),
            file_name="certichain_audit.csv",
            mime="text/csv"
        )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.download_button(
        "Download Institution Public Key",
        data=public_pem,
        file_name="certichain_public_key.pem",
        mime="application/x-pem-file"
    )

    st.caption(
        "Security note: a local hash chain is tamper-evident, "
        "not a true blockchain. An attacker who can rewrite the "
        "database may rebuild the chain. Independent trusted "
        "checkpoints are needed for stronger evidence."
    )
