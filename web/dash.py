from flask import Flask, render_template, request, jsonify, session, redirect
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
from datetime import datetime, timezone
import os
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Flask sessions

# -------------------------
# Firebase setup
# -------------------------
cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# -------------------------
# Role decorator
# -------------------------
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect("/")
            if session.get("role") != required_role:
                return "Unauthorized", 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

# -------------------------
# User-specific collections
# -------------------------
def patients_ref():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.collection("users").document(user_id).collection("patients")

def schedule_ref():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.collection("users").document(user_id).collection("schedules")

# -------------------------
# Pages (Public)
# -------------------------
@app.route("/")
def login():
    return render_template("login.html")

@app.route("/forgot_password")
def forgot_password():
    return render_template("forgot.html")

# -------------------------
# USER PAGES (role = user)
# -------------------------
@app.route("/dashboard")
@role_required("user")
def dashboard():
    return render_template("dashboard.html")

@app.route("/record")
@role_required("user")
def record():
    return render_template("record.html")

@app.route("/schedule")
@role_required("user")
def schedule():
    return render_template("schedule.html")

@app.route("/settings")
@role_required("user")
def settings():
    return render_template("settings.html")

# -------------------------
# ADMIN PAGES (role = admin)
# -------------------------
@app.route("/admin")
def admin_page():
    return render_template("admin.html")  # Admin login page

@app.route("/adminboard")
@role_required("admin")
def adminboard():
    return render_template("adminboard.html")

# -------------------------
# Firebase login verification with auto-create Firestore user
# -------------------------
@app.route("/firebase_login", methods=["POST"])
def firebase_login():
    data = request.json
    id_token = data.get("idToken")
    if not id_token:
        return "No token provided", 400

    for _ in range(3):
        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
            uid = decoded_token["uid"]
            email = decoded_token.get("email")

            user_doc_ref = db.collection("users").document(uid)
            user_doc = user_doc_ref.get()

            # Auto-create Firestore user doc
            if not user_doc.exists:
                user_doc_ref.set({
                    "email": email,
                    "role": "user"       # default role
                })
                role = "user"
            else:
                role = user_doc.to_dict().get("role", "user")

            # Set session
            session["user_id"] = uid
            session["role"] = role

            return "OK", 200

        except Exception as e:
            if "Token used too early" in str(e):
                time.sleep(1)
            else:
                return str(e), 400

    return "Token verification failed after retries", 400

# -------------------------
# Admin login verification
# -------------------------
@app.route("/admin_login_verify", methods=["POST"])
def admin_login_verify():
    data = request.json
    id_token = data.get("idToken")
    if not id_token:
        return jsonify({"error": "No token provided"}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token["uid"]
        user_doc = db.collection("users").document(uid).get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        role = user_doc.to_dict().get("role", "user")
        if role != "admin":
            return jsonify({"error": "Not an admin"}), 403

        session["user_id"] = uid
        session["role"] = "admin"

        return jsonify({"message": "Admin login successful"})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# -------------------------
# Logout
# -------------------------
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("role", None)
    return redirect("/")

# -------------------------
# ADMINBOARD APIs
# -------------------------

@app.route("/api/admin/get_users")
@role_required("admin")
def admin_get_users():
    try:
        docs = db.collection("users").stream()
        users = []
        for doc in docs:
            data = doc.to_dict()
            users.append({
                "uid": doc.id,
                "name": data.get("name") or "-",
                "email": data.get("email") or "-",
                "phone": data.get("phone") or "-"
            })
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/create_user", methods=["POST"])
@role_required("admin")
def admin_create_user():
    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone", "").strip()

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required"}), 400

    # -------------------------
    # Convert Philippine phone to E.164 format
    # -------------------------
    if phone:
        if phone.startswith("0") and len(phone) >= 10:
            phone = "+63" + phone[1:]  # Convert 0XXXXXXXXX → +63XXXXXXXXX
        elif not phone.startswith("+"):
            return jsonify({"error": "Phone number must start with 0 or +[country code]"}), 400

    try:
        # Create user in Firebase Authentication
        user_record = firebase_auth.create_user(
            email=email,
            password=password,
            display_name=name,
            phone_number=phone if phone else None
        )

        # Save user info in Firestore with role = "user"
        db.collection("users").document(user_record.uid).set({
            "name": name,
            "email": email,
            "phone": phone if phone else None,
            "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat()
        })

        return jsonify({"message": f"User {name} created successfully", "uid": user_record.uid})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/delete_user/<uid>", methods=["DELETE"])
@role_required("admin")
def admin_delete_user(uid):
    try:
        # Delete from Firebase Auth
        firebase_auth.delete_user(uid)
        # Delete from Firestore
        db.collection("users").document(uid).delete()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
# -------------------------
# API helpers
# -------------------------
def parse_int(value):
    try: return int(value)
    except: return 0

def parse_float(value):
    try: return float(value)
    except: return 0.0

def serialize_record(record):
    serialized = record.copy()
    ca = serialized.get("created_at")
    if isinstance(ca, dict) and "_seconds" in ca:
        serialized["created_at"] = datetime.utcfromtimestamp(ca["_seconds"]).isoformat()
    elif isinstance(ca, datetime):
        serialized["created_at"] = ca.isoformat()
    elif ca is None:
        serialized["created_at"] = None
    return serialized

# -------------------------
# API: save record
# -------------------------
@app.route("/api/save_record", methods=["POST"])
def save_record():
    user_patients_ref = patients_ref()
    user_schedule_ref = schedule_ref()
    if not user_patients_ref or not user_schedule_ref:
        return jsonify({"error": "Not logged in"}), 401

    data = request.json
    if not data: return jsonify({"error": "No data"}), 400

    try:
        vitals = data.get("vital_signs", {})
        record_data = {
            "name": data.get("name"),
            "age": data.get("age"),
            "sex": data.get("sex"),
            "address": data.get("address"),
            "civil_status": data.get("civil_status"),
            "occupation": data.get("occupation"),
            "bp": parse_int(vitals.get("bp")),
            "cr": parse_int(vitals.get("cr")),
            "rr": parse_int(vitals.get("rr")),
            "temp": parse_float(vitals.get("temp")),
            "spo2": parse_int(vitals.get("spo2")),
            "subjective": data.get("subjective"),
            "physical_exam": data.get("physical_exam"),
            "diagnosis": data.get("diagnosis"),
            "therapeutic_plan": data.get("therapeutic_plan"),
            "follow_up": data.get("follow_up"),
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        patient_id = data.get("patient_id")
        if patient_id:
            doc_ref = user_patients_ref.document(patient_id)
            doc = doc_ref.get()
            if not doc.exists: return jsonify({"error": "Patient not found"}), 404
            existing_data = doc.to_dict()
            records = existing_data.get("records", [])
            records.append(record_data)
            doc_ref.update({
                "name": record_data["name"],
                "age": record_data["age"],
                "sex": record_data["sex"],
                "address": record_data["address"],
                "civil_status": record_data["civil_status"],
                "occupation": record_data["occupation"],
                "records": records
            })
        else:
            patient_doc = {
                "name": record_data["name"],
                "age": record_data["age"],
                "sex": record_data["sex"],
                "address": record_data["address"],
                "civil_status": record_data["civil_status"],
                "occupation": record_data["occupation"],
                "records": [record_data.copy()]
            }
            doc_ref = user_patients_ref.add(patient_doc)
            patient_id = doc_ref[1].id

        follow_up_date = (record_data.get("follow_up") or "").strip()
        if follow_up_date:
            user_schedule_ref.add({
                "patient_id": patient_id,
                "name": record_data["name"],
                "date": follow_up_date,
                "reason": record_data.get("diagnosis") or "Follow-up",
                "status": "Waiting"
            })

        return jsonify({"message": "Record saved", "patient_id": patient_id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------------
# API: get patients
# -------------------------
@app.route("/api/get_patients")
def get_patients():
    user_patients_ref = patients_ref()
    if not user_patients_ref: return jsonify([])
    docs = user_patients_ref.stream()
    patients = []
    for doc in docs:
        data = doc.to_dict()
        patients.append({
            "id": doc.id,
            "name": data.get("name") or "-",
            "age": data.get("age") or "-",
            "sex": data.get("sex") or "-",
            "address": data.get("address") or "-",
            "civil_status": data.get("civil_status") or "-",
            "occupation": data.get("occupation") or "-"
        })
    return jsonify(patients)

# -------------------------
# API: get patient records
# -------------------------
@app.route("/api/get_patient_records/<patient_id>")
def get_patient_records(patient_id):
    user_patients_ref = patients_ref()
    if not user_patients_ref: return jsonify([])
    doc = user_patients_ref.document(patient_id).get()
    if not doc.exists: return jsonify([])
    data = doc.to_dict()
    records = data.get("records", [])
    return jsonify([serialize_record(r) for r in records])

# -------------------------
# API: get schedule
# -------------------------
@app.route("/api/get_schedule")
def get_schedule():
    user_schedule_ref = schedule_ref()
    if not user_schedule_ref: return jsonify([])
    query_date = request.args.get("date")
    docs = user_schedule_ref.stream()
    appointments = []
    for doc in docs:
        data = doc.to_dict()
        app_date = data.get("date")
        if not app_date: continue
        if query_date and app_date != query_date: continue
        appointments.append({
            "date": app_date,
            "patient": data.get("name") or "-",
            "reason": data.get("reason") or "-",
            "status": data.get("status") or "Waiting"
        })
    appointments.sort(key=lambda x: x["date"])
    return jsonify(appointments)

@app.route("/api/save_questionnaire", methods=["POST"])
@role_required("user")
def save_questionnaire():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not logged in"}), 401

    data = request.json
    if not data or "questionnaire" not in data:
        return jsonify({"error": "No questionnaire data provided"}), 400

    questionnaire = data["questionnaire"]

    # If nothing to save, return early
    if not questionnaire:
        return jsonify({"message": "No new sections to save!"})

    try:
        # Save under the current user in Firestore
        db.collection("users").document(user_id).collection("questionnaires").add({
            "questionnaire": questionnaire,
            "created_at": datetime.now(timezone.utc)
        })

        return jsonify({"message": "Questionnaire saved successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)