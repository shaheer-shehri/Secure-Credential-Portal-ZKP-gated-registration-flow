from flask_wtf import FlaskForm
from wtforms import StringField , PasswordField , SubmitField, TextAreaField, SelectField, HiddenField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from web_project.model import User
from flask_wtf.file import FileField, FileAllowed, FileSize
import enum


class ComplaintCategory(str,enum.Enum):
    IT = 'IT Issues (eg., Wifi, PC, Software)'
    ACADEMIC = 'Academic Issues (eg., Grades, Courses)'
    ADMINISTRATIVE = 'Administrative Issues (eg., Registration, Fees)'
    FACILITY = 'Facility Issues (eg., Library, Labs, Classrooms)'
    OTHER = 'Other Issues'

COUNSELOR_CHOICES = [
    ('', '-- Select Counselor Email --'), # Add a placeholder
    ('Mariam.AlDhaheri1@actvet.gov.ae', 'Mariam.AlDhaheri1@actvet.gov.ae'),
    ('Maitha.alnuaimi@actvet.gov.ae', 'Maitha.alnuaimi@actvet.gov.ae'),
    ('noura.alotaibi@actvet.gov.ae', 'noura.alotaibi@actvet.gov.ae'),
    ('Mariam.Alsaadi@actvet.gov.ae', 'Mariam.Alsaadi@actvet.gov.ae'),
    ('fakhara.alkalbani@actvet.gov.ae', 'fakhara.alkalbani@actvet.gov.ae'),
    ('Rouda.AlNuaimi@actvet.gov.ae', 'Rouda.AlNuaimi@actvet.gov.ae')
]

SECTION_CHOICES = [
    ('', '-- Select Section --'), # Placeholder
    ('A06[ADV]/01', 'A06[ADV]/01'),
    ('A06[ADV]/02', 'A06[ADV]/02'),
    ('A06[ADV]/03', 'A06[ADV]/03'),
    ('A06[ADV]/04', 'A06[ADV]/04'),
    ('A06[ADV]/05', 'A06[ADV]/05'),
    ('A06[ADV]/51', 'A06[ADV]/51'),
    ('A06[ADV]/52', 'A06[ADV]/52'),
    ('A06[ADV]/53', 'A06[ADV]/53'),
    ('A06[ADV]/54', 'A06[ADV]/54'),
    ('A07[ADV]/01', 'A07[ADV]/01'),
    ('A07[ADV]/02', 'A07[ADV]/02'),
    ('A07[ADV]/03', 'A07[ADV]/03'),
    ('A07[ADV]/04', 'A07[ADV]/04'),
    ('A07[ADV]/05', 'A07[ADV]/05'),
    ('A07[ADV]/06', 'A07[ADV]/06'),
    ('A07[ADV]/07', 'A07[ADV]/07'),
    ('A07[ADV]/08', 'A07[ADV]/08'),
    ('A07[ADV]/09', 'A07[ADV]/09'),
    ('A07[ADV]/51', 'A07[ADV]/51'),
    ('A07[ADV]/52', 'A07[ADV]/52'),
    ('A07[ADV]/53', 'A07[ADV]/53'),
    ('A07[ADV]/54', 'A07[ADV]/54'),
    ('A07[ADV]/55', 'A07[ADV]/55'),
    ('A07[ADV]/56', 'A07[ADV]/56'),
    ('A07[ADV]/57', 'A07[ADV]/57'),
    ('A08[ADV]/01', 'A08[ADV]/01'),
    ('A08[ADV]/02', 'A08[ADV]/02'),
    ('A08[ADV]/03', 'A08[ADV]/03'),
    ('A08[ADV]/04', 'A08[ADV]/04'),
    ('A08[ADV]/05', 'A08[ADV]/05'),
    ('A08[ADV]/06', 'A08[ADV]/06'),
    ('A08[ADV]/07', 'A08[ADV]/07'),
    ('A08[GEN]/51', 'A08[GEN]/51'),
    ('A08[GEN]/52', 'A08[GEN]/52'),
    ('A08[GEN]/53', 'A08[GEN]/53'),
    ('A08[GEN]/54', 'A08[GEN]/54'),
    ('A08[GEN]/55', 'A08[GEN]/55'),
    ('A08[GEN]/56', 'A08[GEN]/56'),
    ('A08[GEN]/57', 'A08[GEN]/57'),
    ('A09[ADV]/01', 'A09[ADV]/01'),
    ('A09[ASP]/01', 'A09[ASP]/01'),
    ('A09[ADV]/02', 'A09[ADV]/02'),
    ('A09[ADV]/03', 'A09[ADV]/03'),
    ('A09[ADV]/04', 'A09[ADV]/04'),
    ('A09[ADV]/05', 'A09[ADV]/05'),
    ('A09[ASP]/51', 'A09[ASP]/51'),
    ('A09[ADV]/51', 'A09[ADV]/51'),
    ('A09[ADV]/52', 'A09[ADV]/52'),
    ('A09[ADV]/53', 'A09[ADV]/53'),
    ('A09[ADV]/54', 'A09[ADV]/54'),
    ('A09[ADV]/55', 'A09[ADV]/55'),
    ('A09[ADV]/56', 'A09[ADV]/56'),
    ('A09[ADV]/57', 'A09[ADV]/57'),
    ('A10[ASP]/01', 'A10[ASP]/01'),
    ('A10[CAI]/01', 'A10[CAI]/01'),
    ('A10[ENI]/01', 'A10[ENI]/01'),
    ('A10[ENI]/02', 'A10[ENI]/02'),
    ('A10[AET][AMT]/01', 'A10[AET][AMT]/01'),
    ('A10[AMT]/01', 'A10[AMT]/01'),
    ('A10[ASP]/51', 'A10[ASP]/51'),
    ('A10[ENI]/51', 'A10[ENI]/51'),
    ('A10[ENI]/52', 'A10[ENI]/52'),
    ('A10[CAI]/51', 'A10[CAI]/51'),
    ('A10[AHS]/51', 'A10[AHS]/51'),
    ('A10[AHS]/52', 'A10[AHS]/52'),
    ('A10[AHC]/51', 'A10[AHC]/51'),
    ('A10[AET]/51', 'A10[AET]/51'),
    ('A11[ASP]/01', 'A11[ASP]/01'),
    ('A11[ENM]/01', 'A11[ENM]/01'),
    ('A11[CAI]/01', 'A11[CAI]/01'),
    ('A11[AEW][AMT]/01', 'A11[AEW][AMT]/01'),
    ('A11[ASP]/51', 'A11[ASP]/51'),
    ('A11[ENE]/51', 'A11[ENE]/51'),
    ('A11[CAI]/51', 'A11[CAI]/51'),
    ('A11[ENE]/52', 'A11[ENE]/52'),
    ('A11[AHS]/51', 'A11[AHS]/51'),
    ('A11[AHS]/52', 'A11[AHS]/52'),
    ('A11[AEL]/51', 'A11[AEL]/51'),
    ('A11[AHC]/51', 'A11[AHC]/51'),
    ('A12[ASP]/01', 'A12[ASP]/01'),
    ('A12[ENI]/01', 'A12[ENI]/01'),
    ('A12[CAI]/01', 'A12[CAI]/01'),
    ('A12[ENI][CAI]/01', 'A12[ENI][CAI]/01'),
    ('A12[AEW][AMT]/01', 'A12[AEW][AMT]/01'),
    ('A12[ENI]/51', 'A12[ENI]/51'),
    ('A12[ASP]/51', 'A12[ASP]/51'),
    ('A12[AET]/51', 'A12[AET]/51'),
    ('A12[ENI][CAI]/51', 'A12[ENI][CAI]/51'),
    ('A12[AHS]/51', 'A12[AHS]/51'),
    ('A12[CNT][AHC]/51', 'A12[CNT][AHC]/51')
]


class UserForm (FlaskForm):
    def validate_student_id(self, student_id_to_check):
        user = User.query.filter_by(student_id=student_id_to_check.data).first()
        if user:
            raise ValidationError('User ID already exists! Please try a different User ID.')
    
    def validate_email(self,email_address_to_check):
        user = User.query.filter_by(email=email_address_to_check.data).first()
        if user:
            raise ValidationError('Email already taken! Please try using a different Email address')

    student_id = StringField(label='Student ID:',validators=[Length(min=5,max=30),DataRequired()])
    first_name = StringField(label='First Name',validators=[DataRequired()])
    last_name = StringField(label='Last Name',validators=[DataRequired()])
    email = StringField(label = 'Email Address:',validators=[Email(),DataRequired()])

    section = SelectField(
        label='Select Section:',
        choices=SECTION_CHOICES,
        validators=[DataRequired(message="Please select your section.")]
    )
    counselor_email = SelectField(
        label='Select Counselor Email:',
        choices=COUNSELOR_CHOICES,
        validators=[DataRequired(message="Please select your counselor.")]
    )
    
    auth_key = PasswordField(label='Credential Authentication Key:', validators=[DataRequired(), Length(min=6, max=64)])
    password = PasswordField(label = 'Password:',validators=[Length(min=8),DataRequired()])
    password_confirm = PasswordField(label = 'Confirm Password:',validators=[EqualTo('password'), DataRequired()])
    face_image_base64 = HiddenField(label='Register Face:', validators=[DataRequired()])
    
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    login_identifier = StringField(label='Email or Student ID:', validators=[DataRequired()])
    password = PasswordField(label='Password:',validators = [DataRequired()])
    submit = SubmitField(label='Sign in')

class LeaveForm(FlaskForm):
    sick_leave_file = FileField(label='Upload Certificate:', validators=[
        DataRequired(),
        FileAllowed(['jpg', 'png', 'jpeg', 'pdf'], 'Images or PDF only!')
    ])
    submit = SubmitField(label='Submit to Counselor')

class ComplaintForm(FlaskForm):
    category = SelectField(label='Category:', choices=[(cat.name, cat.value) for cat in ComplaintCategory], validators=[DataRequired()])
    description = TextAreaField(label='Description:',validators=[DataRequired(),Length(max=500)])
    submit = SubmitField(label='Submit Complaint')


class PasswordResetForm(FlaskForm):
    student_id = StringField(label='Student ID:', validators=[DataRequired()])
    verify_face_image_base64 = HiddenField(label='Verify Face:', validators=[DataRequired()])
    submit = SubmitField(label='Verify Student')

class PasswordResetSetForm(FlaskForm):
    student_id = HiddenField()

    new_password = PasswordField(label = 'New Password:',validators=[Length(min=8),DataRequired()])
    confirm_password = PasswordField(label = 'Confirm New Password:',validators=[EqualTo('new_password'), DataRequired()])
    submit = SubmitField(label='Reset Password')


class IssuerCredentialForm(FlaskForm):
    student_id = StringField(label='Student ID', validators=[DataRequired(), Length(max=30)])
    first_name = StringField(label='First Name', validators=[DataRequired()])
    last_name = StringField(label='Last Name', validators=[DataRequired()])
    program = StringField(label='Program / Department', validators=[DataRequired()])
    valid_days = SelectField(
        label='Credential Validity Window',
        choices=[('7', '7 days'), ('30', '30 days'), ('90', '90 days'), ('999999', 'Until revoked')],
        default='30',
        validators=[DataRequired()],
    )
    issuer_notes = TextAreaField(label='Notes for Certificate (optional)', validators=[Length(max=300)])
    id_document = FileField(label='Upload ID / Enrollment Proof', validators=[
        DataRequired(message='Please attach the official ID proof.'),
        FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], 'Allowed formats: JPG, PNG, PDF.')
    ])
    selfie_image_base64 = HiddenField(label='Capture Live Selfie', validators=[DataRequired()])
    submit = SubmitField(label='Mint Credential')


class VerificationRequestForm(FlaskForm):
    student_id = StringField(label='Student ID', validators=[DataRequired(), Length(min=4, max=30)])
    first_name = StringField(label='First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField(label='Last Name', validators=[DataRequired(), Length(max=50)])
    email = StringField(label='Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    section = SelectField(label='Section', choices=SECTION_CHOICES, validators=[DataRequired(message='Please select your section.')])
    notes = TextAreaField(label='Additional Details (optional)', validators=[Length(max=400)])
    submit = SubmitField(label='Send Verification Request')
