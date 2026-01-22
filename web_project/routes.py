from datetime import datetime, timedelta,timezone
from flask import render_template, redirect, url_for, flash, request, session
from web_project import app, db, bcrypt, mail
from flask_mail import Message
from web_project import login_manager 
from web_project.forms import (
    UserForm, LoginForm, ComplaintForm, LeaveForm,
    PasswordResetForm, PasswordResetSetForm, VerificationRequestForm
)
from web_project.model import User, CredentialVerification, SecurityEvent, IssuerAccount, VerificationRequest
from web_project.security import hash_auth_key
from web_project.risk import assess_signup_risk
from web_project.security_events import record_security_event
from web_project.zkp_runtime import runtime_manifest
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from sqlalchemy import func
import os
import face_recognition
import uuid
import re
import base64

UTC = timezone.utc
def save_base64_image(data_url):
    """Decodes a Base64 data URL and saves it to a unique file."""
    try:
        # Split the "data:image/jpeg;base64," prefix from the data
        header, encoded = data_url.split(",", 1)
        # Get the file extension
        ext = re.search(r'/(.*?);', header).group(1)
        
        data = base64.b64decode(encoded)
        
        # Create a unique filename
        filename = f"{uuid.uuid4()}.{ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(file_path, "wb") as f:
            f.write(data)
            
        return file_path
    except Exception as e:
        print(f"Error saving Base64 image: {e}")
        return None

def save_file(file_storage):
    """Saves a file with a unique name to the upload folder."""

    ext = file_storage.filename.split('.')[-1]
    # Create a unique filename
    filename = f"{uuid.uuid4()}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_storage.save(file_path)
    return file_path

def face_matching(image1_path, image2_path) -> bool:
    if not os.path.exists(image1_path) or not os.path.exists(image2_path):
        print(f"Error: File not found. {image1_path} or {image2_path}")
        return False
    try:
        image1 = face_recognition.load_image_file(image1_path)
        image2 = face_recognition.load_image_file(image2_path)

        encodings1 = face_recognition.face_encodings(image1)
        encodings2 = face_recognition.face_encodings(image2)

        if len(encodings1) == 0 or len(encodings2) == 0:
            print("Error: No face found in one or both images.")
            return False

        enc1 = encodings1[0]
        enc2 = encodings2[0]
        matches = face_recognition.compare_faces([enc1], enc2, tolerance=0.6)
        distance = face_recognition.face_distance([enc1], enc2)[0]
        print(f"Face distance: {distance:.4f}")
        return matches[0]
    except Exception as e:
        print(f"Error during face matching: {e}")
        return False



def send_admin_notification(counselor_email, subject, body, attachment_path=None): # Renamed for clarity
    """Sends an email notification to the configured ADMIN_EMAIL."""
    target_email = counselor_email
    if not target_email:
        print("!!! ERROR: ADMIN_EMAIL not configured in Flask app. Cannot send email. !!!")
        return

    try:
        msg = Message(
            subject=subject,
            recipients=[target_email] # Always send to the admin email
            # Sender still comes from MAIL_DEFAULT_SENDER/MAIL_USERNAME
        )
        msg.body = body

        # Handle attachments (no changes needed here)
        if attachment_path and os.path.exists(attachment_path):
            with app.open_resource(attachment_path, 'rb') as fp:
                ctype = 'application/octet-stream'
                filename = os.path.basename(attachment_path)
                ext = filename.split('.')[-1].lower()
                if ext in ['jpg', 'jpeg']: ctype = 'image/jpeg'
                elif ext == 'png': ctype = 'image/png'
                elif ext == 'pdf': ctype = 'application/pdf'
                
                msg.attach(filename=filename, content_type=ctype, data=fp.read())

        mail.send(msg)
        print(f"--- Admin Notification SENT successfully to {target_email} ---")

    except Exception as e:
        print(f"!!! FAILED to send admin notification email to {target_email}: {e} !!!")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def render_home(**context):
    context.setdefault('zk_manifest', runtime_manifest())
    return render_template('home.html', **context)

@app.route('/')
def home():
    """
    This is the MAIN route. It displays the home.html template.
    It passes *empty* forms to the template so they can be rendered.
    It also checks for a 'page' argument to know which section to show.
    """
    # Get the page to show from the URL (e.g., /?page=page-login)
    show_page = request.args.get('page', 'page-main-menu')
    
    # Pass all forms that can be *initiated* from the home page
    forms = {
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    
    # For the password reset 'set' page, we need to pass the user_id
    if show_page == 'page-password-new':
        user_student_id = request.args.get('student_id')
        forms['password_set_form'].student_id.data = user_student_id
    credential_verified = session.get('credential_verified')
    if credential_verified and credential_verified.get('token'):
        record = CredentialVerification.query.filter_by(session_token=credential_verified['token']).first()
        if not record or not record.is_active():
            session.pop('credential_verified', None)
            credential_verified = None
    if credential_verified:
        forms['signup_form'].student_id.data = credential_verified.get('student_id', '')
        forms['signup_form'].first_name.data = credential_verified.get('first_name', '')
        forms['signup_form'].last_name.data = credential_verified.get('last_name', '')

    return render_home(
        **forms,
        show_page=show_page,
        credential_verified=credential_verified,
    )

@app.route('/signup', methods=['POST'])
def signup():
    credential_verified = session.get('credential_verified')
    if not credential_verified:
        flash('Please run the NUST credential verification flow before creating an account.', 'danger')
        record_security_event(
            'signup_without_verification',
            severity='medium',
            detail='Signup attempted without credential verification session.',
        )
        return redirect(url_for('home', page='page-credential'))

    verification_record = None
    token = credential_verified.get('token')
    issued_record = None
    if token:
        verification_record = CredentialVerification.query.filter_by(session_token=token).first()
        if verification_record:
            issued_record = verification_record.credential

    if not verification_record or not verification_record.is_active():
        session.pop('credential_verified', None)
        flash('Credential verification expired. Please re-run the verifier before signing up.', 'danger')
        record_security_event(
            'signup_verification_expired',
            severity='low',
            detail='Signup attempted with expired verification token.',
        )
        return redirect(url_for('home', page='page-credential'))

    form = UserForm()
    if form.validate_on_submit():
        if verification_record.student_id != form.student_id.data:
            flash('Student ID does not match the verified credential. Re-run verification to continue.', 'danger')
            record_security_event(
                'signup_student_id_mismatch',
                severity='medium',
                detail='Signup student ID did not match verification token.',
            )
            return redirect(url_for('home', page='page-credential'))

        if form.student_id.data != credential_verified.get('student_id'):
            flash('Student ID does not match the verified credential. Re-run verification to continue.', 'danger')
            record_security_event(
                'signup_student_id_session_mismatch',
                severity='medium',
                detail='Signup student ID mismatched session snapshot.',
            )
            return redirect(url_for('home', page='page-credential'))

        if form.first_name.data.strip().lower() != credential_verified.get('first_name', '').strip().lower():
            flash('First name does not match the verified credential.', 'danger')
            record_security_event(
                'signup_first_name_mismatch',
                severity='low',
                detail='Signup first name mismatched verified credential.',
            )
            return redirect(url_for('home', page='page-credential'))

        if form.last_name.data.strip().lower() != credential_verified.get('last_name', '').strip().lower():
            flash('Last name does not match the verified credential.', 'danger')
            record_security_event(
                'signup_last_name_mismatch',
                severity='low',
                detail='Signup last name mismatched verified credential.',
            )
            return redirect(url_for('home', page='page-credential'))

        auth_key_value = (form.auth_key.data or '').strip()
        expected_hash = issued_record.auth_key_hash if issued_record else None
        if expected_hash and hash_auth_key(auth_key_value) != expected_hash:
            flash('Authentication key does not match the issued credential.', 'danger')
            record_security_event(
                'signup_auth_key_mismatch',
                severity='high',
                detail='Signup authentication key hash mismatch.',
                metadata={'credential_id': issued_record.id if issued_record else None},
            )
            return redirect(url_for('home', page='page-signup-start'))

        request_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        verified_at = verification_record.verified_at_utc() or datetime.now(UTC)
        minutes_since_verification = (
            datetime.now(UTC) - verified_at
        ).total_seconds() / 60.0
        window_start = datetime.now(UTC) - timedelta(hours=6)
        recent_failures = SecurityEvent.query.filter(
            SecurityEvent.ip_address == request_ip,
            SecurityEvent.created_at >= window_start,
            SecurityEvent.severity.in_(['medium', 'high'])
        ).count()
        verification_ip = credential_verified.get('ip_address') or getattr(verification_record, 'ip_address', None)

        risk_assessment = assess_signup_risk(
            minutes_since_verification=minutes_since_verification,
            recent_failure_events=recent_failures,
            verification_ip=verification_ip,
            request_ip=request_ip,
        )

        if risk_assessment.level == 'high':
            record_security_event(
                'signup_high_risk_blocked',
                severity='high',
                detail='Adaptive risk engine blocked signup.',
                metadata={
                    'reasons': risk_assessment.reasons,
                    'minutes_since_verification': minutes_since_verification,
                    'recent_failures': recent_failures,
                },
            )
            flash('We detected unusual activity. Please re-run the verification flow or contact the issuer.', 'danger')
            return redirect(url_for('home', page='page-credential'))
        elif risk_assessment.level == 'medium':
            flash('Proceeding with caution: ' + '; '.join(risk_assessment.reasons), 'warning')

        existing_user = User.query.filter(
            (User.student_id == form.student_id.data) |
            (User.email == form.email.data)
        ).first()
        if existing_user:
            flash('An account already exists for this student. Please log in or reset your password.', 'warning')
            record_security_event(
                'signup_duplicate_account',
                severity='low',
                detail='Signup attempted for already-registered student.',
                metadata={'student_id': form.student_id.data, 'email': form.email.data}
            )
            return redirect(url_for('home', page='page-login'))

        # --- CHANGE HERE ---
        # Instead of saving a file, we decode the Base64 string
        face_path = save_base64_image(form.face_image_base64.data)
        if not face_path:
            flash('There was an error processing your face image. Please try again.', 'danger')
            # Re-render the form page (see below for how to handle this)
            return redirect(url_for('home', page='page-signup-start')) # Simplified redirect

        # Create new user
        user = User(
            student_id=form.student_id.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=form.password.data, # The setter in models.py handles hashing
            section=form.section.data,
            counselor_email=form.counselor_email.data,
            image_path=face_path # Save the path to the DB
        )
        db.session.add(user)
        verification_record.consume()
        db.session.commit()
        session.pop('credential_verified', None)
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('home', page='page-login'))

    forms = {
        'login_form': LoginForm(),
        'signup_form': form,
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    if credential_verified:
        forms['signup_form'].student_id.data = credential_verified.get('student_id', '')
        forms['signup_form'].first_name.data = credential_verified.get('first_name', '')
        forms['signup_form'].last_name.data = credential_verified.get('last_name', '')
    flash('Please correct the errors in the sign-up form.', 'danger')
    return render_template(
        'home.html',
        **forms,
        show_page='page-signup-start',
        credential_verified=credential_verified,
    )

@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.login_identifier.data.strip()
        user = User.query.filter(
            (User.email == identifier) |
            (User.student_id == identifier)
        ).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            if getattr(user, 'is_issuer', False):
                session['issuer_account_id'] = user.id
                session['issuer_account_email'] = user.email
                flash('Issuer console unlocked. You can now mint credentials.', 'success')
                return redirect(url_for('issuer.dashboard'))
            session.pop('issuer_account_id', None)
            session.pop('issuer_account_email', None)
            flash(f'Login Successful! Welcome, {user.first_name}.', 'success')
            return redirect(url_for('home', page='page-logged-in-menu'))

        issuer_candidate = None
        if '@' in identifier:
            issuer_candidate = IssuerAccount.query.filter(
                func.lower(IssuerAccount.email) == identifier.lower()
            ).first()

        if issuer_candidate and issuer_candidate.check_password(form.password.data):
            session['issuer_account_id'] = issuer_candidate.id
            session['issuer_account_email'] = issuer_candidate.email
            flash('Issuer console unlocked. You can now mint credentials.', 'success')
            return redirect(url_for('issuer.dashboard'))

        flash('Login Unsuccessful. Please check email/ID and password.', 'danger')
        return redirect(url_for('home', page='page-login'))


    forms = {
        'login_form': form,
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    return render_home(**forms, show_page='page-login')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('issuer_account_id', None)
    session.pop('issuer_account_email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))



@app.route('/submit-sick-leave', methods=['POST'])
@login_required
def submit_leave():
    form = LeaveForm()
    if form.validate_on_submit():
        file_path = save_file(form.sick_leave_file.data)
        
        subject = f"Leave Submission - {current_user.first_name} {current_user.last_name}"
        body = f"Student {current_user.first_name} (ID: {current_user.student_id}, Counselor Email: {current_user.counselor_email}) has submitted a leave certificate."

        send_admin_notification(
            counselor_email=current_user.counselor_email,
            subject=subject,
            body=body,
            attachment_path=file_path
        )
        
        flash('Leave submitted.', 'success')
        return redirect(url_for('home', page='page-logged-in-menu'))

    forms = {
        'leave_form': form,
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    flash('There was an error uploading your file. Please try again.', 'danger')
    return render_home(**forms, show_page='page-sick-leave')


@app.route('/submit-complaint', methods=['POST'])
@login_required
def submit_complaint():
    form = ComplaintForm()
    if form.validate_on_submit():
        subject = f"New Complaint ({form.category.data}) - {current_user.first_name}"
        body = f"""
        Student: {current_user.first_name} {current_user.last_name} (ID: {current_user.student_id})
        Registered Counselor Email: {current_user.counselor_email}
        Category: {form.category.data}
        
        Description:
        {form.description.data}
        """
        send_admin_notification(
            counselor_email=current_user.counselor_email,
            subject=subject,
            body=body
        )
        
        flash('Your complaint has been submitted.', 'success')
        return redirect(url_for('home', page='page-logged-in-menu'))

    # If form fails validation
    forms = {
        'complaint_form': form,
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    return render_home(**forms, show_page='page-complaint')


@app.route('/request-verification', methods=['POST'])
def request_verification():
    form = VerificationRequestForm()
    if form.validate_on_submit():
        verification_request = VerificationRequest(
            student_id=form.student_id.data.strip(),
            section=form.section.data,
            first_name=form.first_name.data.strip(),
            last_name=form.last_name.data.strip(),
            email=form.email.data.strip(),
            notes=form.notes.data,
        )
        db.session.add(verification_request)
        db.session.commit()

        admin_email = app.config.get('ADMIN_EMAIL') or app.config.get('MAIL_USERNAME')
        subject = f"Verification Request - {form.student_id.data}"
        body = (
            "A student asked the security desk to mint a zero-knowledge credential.\n\n"
            f"Student ID: {form.student_id.data}\n"
            f"Name: {form.first_name.data} {form.last_name.data}\n"
            f"Section: {form.section.data}\n"
            f"Email: {form.email.data}\n\n"
            f"Notes:\n{form.notes.data or 'No additional notes provided.'}\n"
        )
        send_admin_notification(
            counselor_email=admin_email,
            subject=subject,
            body=body,
        )
        flash('Request sent to the verification desk. Expect a response soon.', 'success')
        return redirect(url_for('home', page='page-credential'))

    forms = {
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': form
    }
    flash('Please correct the errors in the verification request form.', 'danger')
    return render_home(**forms, show_page='page-verification-request')


@app.route('/password-reset-verify', methods=['POST'])
def verify_face_image_base64():
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(student_id=form.student_id.data).first()
        if not user:
            flash('Student ID not found.', 'danger')
            return redirect(url_for('home', page='page-password-start'))

        # --- CHANGE HERE ---
        # Save the *temporary* verification image from Base64
        temp_image_path = save_base64_image(form.verify_face_image_base64.data)
        if not temp_image_path:
            flash('There was an error processing your face image. Please try again.', 'danger')
            return redirect(url_for('home', page='page-password-start'))

        # Compare with the user's *registered* image
        is_match = face_matching(user.image_path, temp_image_path)
        
        # Clean up the temporary image
        if os.path.exists(temp_image_path):
             os.remove(temp_image_path)
        
        if is_match:
            flash('Verification Complete! Please set your new password.', 'success')
            return redirect(url_for('home', page='page-password-new', student_id=user.student_id))
        else:
            flash('Face verification failed. Please try again.', 'danger')
            return redirect(url_for('home', page='page-password-start'))
    
    # If form validation fails (e.g. no student_id)
    forms = {
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': form, # Pass back the invalid form
        'password_set_form': PasswordResetSetForm(),
        'verification_request_form': VerificationRequestForm()
    }
    flash('Please provide all required fields.', 'danger')
    return render_home(**forms, show_page='page-password-start')


@app.route('/password-reset-set', methods=['POST'])
def password_reset_set():
    form = PasswordResetSetForm()
    if form.validate_on_submit():
        # Find the user from the hidden student_id field
        user = User.query.filter_by(student_id=form.student_id.data).first()
        if user:
            user.password = form.new_password.data # Use the setter to hash it
            db.session.commit()
            flash('Your password has been reset! You can now log in.', 'success')
            return redirect(url_for('home', page='page-login'))
        else:
            flash('An error occurred. User not found.', 'danger')
            return redirect(url_for('home', page='page-password-start'))
            
    # If form fails (e.g., passwords don't match)
    forms = {
        'login_form': LoginForm(),
        'signup_form': UserForm(),
        'complaint_form': ComplaintForm(),
        'leave_form': LeaveForm(),
        'password_form': PasswordResetForm(),
        'password_set_form': form,
        'verification_request_form': VerificationRequestForm()
    }
    # We must pass the student_id back to the template
    forms['password_set_form'].student_id.data = form.student_id.data
    flash('Passwords do not match. Please try again.', 'danger')
    return render_home(**forms, show_page='page-password-new')