# app.py - Enhanced GDPR Compliance Scanner
import os
import re
import smtplib
import ssl
import socket
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from urllib.parse import urlparse

import OpenSSL
import pdfkit
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_apscheduler import APScheduler
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# Configure pdfkit with path to wkhtmltopdf
config = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_API_ENABLED'] = True

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# Email configuration (example using Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    scans = db.relationship('ScanResult', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    has_https = db.Column(db.Boolean)
    has_privacy_policy = db.Column(db.Boolean)
    privacy_policy_content = db.Column(db.Text)
    cookies_found = db.Column(db.Integer)
    cookie_details = db.Column(db.Text)  # JSON string of cookie details
    tracking_scripts = db.Column(db.Integer)
    tracking_details = db.Column(db.Text)  # JSON string of tracking details
    ssl_details = db.Column(db.Text)  # JSON string of SSL details
    data_forms_found = db.Column(db.Integer)
    consent_mechanism = db.Column(db.Boolean)
    report_path = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    scheduled = db.Column(db.Boolean, default=False)
    next_scan = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'scan_date': self.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            'has_https': self.has_https,
            'has_privacy_policy': self.has_privacy_policy,
            'cookies_found': self.cookies_found,
            'tracking_scripts': self.tracking_scripts,
            'data_forms_found': self.data_forms_found,
            'consent_mechanism': self.consent_mechanism,
            'scheduled': self.scheduled,
            'next_scan': self.next_scan.strftime('%Y-%m-%d %H:%M:%S') if self.next_scan else None
        }

class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    frequency = db.Column(db.String(50), nullable=False)  # daily, weekly, monthly
    next_scan = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    active = db.Column(db.Boolean, default=True)

# Create database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def analyze_cookies(cookies, soup):
    """Perform comprehensive cookie analysis"""
    cookie_details = []
    
    # Analyze cookies from headers
    for cookie in cookies:
        cookie_details.append({
            'name': cookie.split(';')[0].split('=')[0] if '=' in cookie else cookie,
            'source': 'HTTP Header',
            'http_only': 'HttpOnly' in cookie,
            'secure': 'Secure' in cookie,
            'session': 'Expires' not in cookie and 'Max-Age' not in cookie,
            'domain': extract_cookie_attribute(cookie, 'Domain'),
            'path': extract_cookie_attribute(cookie, 'Path'),
            'expires': extract_cookie_attribute(cookie, 'Expires'),
            'same_site': extract_cookie_attribute(cookie, 'SameSite')
        })
    
    # Analyze cookies from JavaScript
    scripts = soup.find_all('script')
    for script in scripts:
        script_content = script.string or ''
        if 'document.cookie' in script_content:
            # Simple pattern matching for cookie setting
            matches = re.findall(r'document\.cookie\s*=\s*([^;]+)', script_content)
            for match in matches:
                cookie_name = match.split('=')[0].strip().strip("'\"")
                cookie_details.append({
                    'name': cookie_name,
                    'source': 'JavaScript',
                    'http_only': False,
                    'secure': False,
                    'session': True,
                    'domain': None,
                    'path': None,
                    'expires': None,
                    'same_site': None
                })
    
    return cookie_details

def extract_cookie_attribute(cookie, attr):
    """Extract specific attribute from cookie string"""
    parts = cookie.split(';')
    for part in parts:
        if attr.lower() in part.lower():
            return part.split('=')[1].strip() if '=' in part else True
    return None

def analyze_privacy_policy(url, soup):
    """Perform deeper privacy policy content analysis"""
    privacy_links = []
    privacy_terms = ['privacy', 'datenschutz', 'gdpr', 'cookie policy', 'data protection']
    
    for term in privacy_terms:
        links = soup.find_all('a', string=lambda text: text and term.lower() in text.lower())
        privacy_links.extend(links)
    
    if not privacy_links:
        return None, None
    
    # Get the first privacy policy link content
    try:
        policy_url = privacy_links[0].get('href')
        if not policy_url.startswith('http'):
            base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))
            policy_url = base_url + ('/' if not policy_url.startswith('/') else '') + policy_url
        
        response = requests.get(policy_url, timeout=10)
        policy_soup = BeautifulSoup(response.text, 'html.parser')
        policy_text = policy_soup.get_text()
        
        # Check for GDPR keywords
        gdpr_keywords = {
            'data subject rights': len(re.findall(r'data subject rights|rights of individuals', policy_text, re.I)),
            'right to access': len(re.findall(r'right to access|access your data', policy_text, re.I)),
            'right to erasure': len(re.findall(r'right to erasure|right to be forgotten', policy_text, re.I)),
            'data portability': len(re.findall(r'data portability', policy_text, re.I)),
            'lawful basis': len(re.findall(r'lawful basis|legal basis', policy_text, re.I)),
            'dpo': len(re.findall(r'data protection officer|dpo', policy_text, re.I)),
            'data breach': len(re.findall(r'data breach|breach notification', policy_text, re.I))
        }
        
        return policy_url, gdpr_keywords
    except Exception:
        return None, None

def check_ssl_details(url):
    """Perform detailed SSL/TLS checks"""
    hostname = urlparse(url).netloc
    if ':' in hostname:
        hostname = hostname.split(':')[0]
    
    context = ssl.create_default_context()
    details = {}
    
    try:
        import socket  # Add this import at the top of your file
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True)))
                
                # Certificate details
                details['valid_from'] = cert_info.get_notBefore().decode('utf-8')
                details['valid_to'] = cert_info.get_notAfter().decode('utf-8')
                details['issuer'] = dict(x[0] for x in cert_info.get_issuer().get_components())
                details['subject'] = dict(x[0] for x in cert_info.get_subject().get_components())
                details['version'] = cert_info.get_version()
                details['serial_number'] = cert_info.get_serial_number()
                
                # Protocol and cipher
                details['protocol'] = ssock.version()
                details['cipher'] = ssock.cipher()
                
                # Check for vulnerabilities
                details['heartbleed_vulnerable'] = is_heartbleed_vulnerable(hostname)
                
                return details
    except Exception as e:
        return {'error': str(e)}

def is_heartbleed_vulnerable(hostname):
    """Check for Heartbleed vulnerability (simplified example)"""
    try:
        # This is a simplified check - real implementation would be more complex
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version() == 'TLSv1'  # Simplified check
    except:
        return False

def check_data_collection_forms(soup):
    """Check for data collection forms"""
    forms = soup.find_all('form')
    data_forms = []
    
    for form in forms:
        inputs = form.find_all('input')
        textareas = form.find_all('textarea')
        selects = form.find_all('select')
        
        # Check for personal data fields
        personal_data_fields = []
        for field in inputs + textareas + selects:
            field_name = field.get('name', '').lower() or field.get('id', '').lower()
            if any(term in field_name for term in ['name', 'email', 'address', 'phone', 'dob', 'birth', 'ssn', 'id']):
                personal_data_fields.append(field_name)
        
        if personal_data_fields:
            data_forms.append({
                'action': form.get('action'),
                'method': form.get('method', 'GET'),
                'personal_data_fields': personal_data_fields
            })
    
    return data_forms

def check_consent_mechanism(soup):
    """Check for GDPR consent mechanisms"""
    # Check for cookie banners
    cookie_banners = soup.find_all(lambda tag: tag.name in ['div', 'section'] and 
                                 'cookie' in (tag.get('id', '') + tag.get('class', '')).lower())
    
    # Check for privacy buttons
    privacy_buttons = soup.find_all(lambda tag: tag.name == 'button' and 
                                  any(term in tag.text.lower() for term in ['accept', 'reject', 'preferences', 'privacy']))
    
    # Check for consent checkboxes
    consent_checkboxes = soup.find_all('input', {'type': 'checkbox'}, 
                                    attrs={'name': lambda x: x and 'consent' in x.lower()})
    
    return len(cookie_banners) > 0 or len(privacy_buttons) > 0 or len(consent_checkboxes) > 0

def scan_website(url):
    """Perform comprehensive GDPR compliance scan on a website"""
    results = {
        'url': url,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'has_https': False,
        'has_privacy_policy': False,
        'privacy_policy_content': None,
        'cookies': [],
        'cookie_details': [],
        'tracking_scripts': [],
        'tracking_details': [],
        'ssl_details': {},
        'data_forms': [],
        'consent_mechanism': False,
        'error': None
    }

    try:
        # Check URL scheme
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'https://' + url
            parsed_url = urlparse(url)

        results['has_https'] = parsed_url.scheme == 'https'

        # Get website content
        headers = {
            'User-Agent': 'GDPRComplianceScanner/2.0'
        }
        response = requests.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Detailed SSL/TLS checks
        if results['has_https']:
            results['ssl_details'] = check_ssl_details(url)

        # Comprehensive cookie analysis
        cookies = response.headers.get('Set-Cookie', '')
        if cookies:
            results['cookies'] = cookies.split(',')
        
        results['cookie_details'] = analyze_cookies(results['cookies'], soup)

        # Tracking script detection
        common_trackers = {
            'Google Analytics': ['google-analytics.com', 'ga.js', 'analytics.js', 'gtag.js'],
            'Facebook': ['facebook.net', 'fbq(', 'connect.facebook.net'],
            'Hotjar': ['hotjar.com', 'hj.js'],
            'LinkedIn': ['linkedin.com', 'licdn.com', 'lnkd.in'],
            'Twitter': ['twitter.com', 'twimg.com', 'platform.twitter.com']
        }

        scripts = soup.find_all('script')
        for script in scripts:
            if script.has_attr('src'):
                src = script['src'].lower()
                for tracker_name, tracker_patterns in common_trackers.items():
                    if any(pattern in src for pattern in tracker_patterns):
                        results['tracking_scripts'].append(src)
                        results['tracking_details'].append({
                            'url': src,
                            'type': tracker_name,
                            'location': 'external'
                        })
            
            # Check for inline tracking
            script_content = script.string or ''
            if script_content:
                for tracker_name, tracker_patterns in common_trackers.items():
                    if any(pattern in script_content.lower() for pattern in tracker_patterns):
                        results['tracking_scripts'].append(f"Inline {tracker_name} code")
                        results['tracking_details'].append({
                            'type': tracker_name,
                            'location': 'inline'
                        })

        # Deep privacy policy analysis
        policy_url, policy_keywords = analyze_privacy_policy(url, soup)
        if policy_url:
            results['has_privacy_policy'] = True
            results['privacy_policy_content'] = {
                'url': policy_url,
                'keywords': policy_keywords
            }

        # Data collection forms
        results['data_forms'] = check_data_collection_forms(soup)

        # Consent mechanism
        results['consent_mechanism'] = check_consent_mechanism(soup)

        return results

    except Exception as e:
        results['error'] = str(e)
        return results

def generate_pdf_report(scan_data):
    """Generate a PDF report from scan data"""
    report_html = render_template('report_template.html', data=scan_data)
    
    # Ensure reports directory exists
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    report_filename = f"reports/gdpr_report_{scan_data['url'].replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    try:
        pdfkit.from_string(report_html, report_filename, configuration=config)
        return report_filename
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def send_email_report(email, scan_data, report_path):
    """Send scan report via email"""
    msg = MIMEMultipart()
    msg['Subject'] = f"GDPR Compliance Report for {scan_data['url']}"
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = email

    # Email body
    body = f"""
    <html>
        <body>
            <h2>GDPR Compliance Report</h2>
            <p>Here is your GDPR compliance report for {scan_data['url']}.</p>
            <p>Scan date: {scan_data['scan_date']}</p>
            
            <h3>Summary</h3>
            <ul>
                <li>HTTPS: {'✅ Enabled' if scan_data['has_https'] else '❌ Disabled'}</li>
                <li>Privacy Policy: {'✅ Found' if scan_data['has_privacy_policy'] else '❌ Not Found'}</li>
                <li>Cookies Found: {len(scan_data['cookie_details'])}</li>
                <li>Tracking Scripts: {len(scan_data['tracking_details'])}</li>
                <li>Data Collection Forms: {len(scan_data['data_forms'])}</li>
                <li>Consent Mechanism: {'✅ Present' if scan_data['consent_mechanism'] else '❌ Missing'}</li>
            </ul>
            
            <p>See attached PDF for full details.</p>
        </body>
    </html>
    """
    
    msg.attach(MIMEText(body, 'html'))

    # Attach PDF
    with open(report_path, 'rb') as f:
        attach = MIMEApplication(f.read(), _subtype="pdf")
        attach.add_header('Content-Disposition', 'attachment', filename=os.path.basename(report_path))
        msg.attach(attach)

    # Send email
    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Scheduled tasks
@scheduler.task('interval', id='scheduled_scans', hours=1, misfire_grace_time=900)
def run_scheduled_scans():
    """Check for and run scheduled scans"""
    with app.app_context():
        due_scans = ScheduledScan.query.filter(
            ScheduledScan.next_scan <= datetime.now(),
            ScheduledScan.active == True
        ).all()

        for scheduled in due_scans:
            user = User.query.get(scheduled.user_id)
            if user:
                scan_data = scan_website(scheduled.url)
                
                # Save scan results
                scan_record = ScanResult(
                    url=scheduled.url,
                    has_https=scan_data.get('has_https', False),
                    has_privacy_policy=scan_data.get('has_privacy_policy', False),
                    privacy_policy_content=str(scan_data.get('privacy_policy_content', '')),
                    cookies_found=len(scan_data.get('cookie_details', [])),
                    cookie_details=str(scan_data.get('cookie_details', [])),
                    tracking_scripts=len(scan_data.get('tracking_details', [])),
                    tracking_details=str(scan_data.get('tracking_details', [])),
                    ssl_details=str(scan_data.get('ssl_details', {})),
                    data_forms_found=len(scan_data.get('data_forms', [])),
                    consent_mechanism=scan_data.get('consent_mechanism', False),
                    user_id=user.id,
                    scheduled=True
                )
                
                # Generate and store report
                report_path = generate_pdf_report(scan_data)
                if report_path:
                    scan_record.report_path = report_path
                
                db.session.add(scan_record)
                
                # Update next scan time
                if scheduled.frequency == 'daily':
                    scheduled.next_scan = datetime.now() + timedelta(days=1)
                elif scheduled.frequency == 'weekly':
                    scheduled.next_scan = datetime.now() + timedelta(weeks=1)
                else:  # monthly
                    scheduled.next_scan = datetime.now() + timedelta(days=30)
                
                db.session.commit()
                
                # Send email notification if user has email
                if user.email and report_path:
                    send_email_report(user.email, scan_data, report_path)

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing scan history"""
    scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.scan_date.desc()).limit(10).all()
    scheduled_scans = ScheduledScan.query.filter_by(user_id=current_user.id, active=True).all()
    return render_template('dashboard.html', scans=scans, scheduled_scans=scheduled_scans)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    """API endpoint to perform a scan"""
    url = request.form.get('url')
    email_report = request.form.get('email_report', 'false') == 'true'
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    scan_data = scan_website(url)
    
    # Save to database
    scan_record = ScanResult(
        url=url,
        has_https=scan_data.get('has_https', False),
        has_privacy_policy=scan_data.get('has_privacy_policy', False),
        privacy_policy_content=str(scan_data.get('privacy_policy_content', '')),
        cookies_found=len(scan_data.get('cookie_details', [])),
        cookie_details=str(scan_data.get('cookie_details', [])),
        tracking_scripts=len(scan_data.get('tracking_details', [])),
        tracking_details=str(scan_data.get('tracking_details', [])),
        ssl_details=str(scan_data.get('ssl_details', {})),
        data_forms_found=len(scan_data.get('data_forms', [])),
        consent_mechanism=scan_data.get('consent_mechanism', False),
        user_id=current_user.id
    )
    
    # Generate and store report
    report_path = generate_pdf_report(scan_data)
    if report_path:
        scan_record.report_path = report_path
    
    db.session.add(scan_record)
    db.session.commit()
    
    # Send email if requested
    email_sent = False
    if email_report and current_user.email and report_path:
        email_sent = send_email_report(current_user.email, scan_data, report_path)
    
    return jsonify({
        'message': 'Scan completed',
        'data': scan_data,
        'scan_id': scan_record.id,
        'email_sent': email_sent
    })

@app.route('/schedule', methods=['POST'])
@login_required
def schedule_scan():
    """Schedule recurring scans"""
    url = request.form.get('url')
    frequency = request.form.get('frequency')
    
    if not url or not frequency:
        return jsonify({'error': 'URL and frequency are required'}), 400
    
    # Calculate next scan time
    if frequency == 'daily':
        next_scan = datetime.now() + timedelta(days=1)
    elif frequency == 'weekly':
        next_scan = datetime.now() + timedelta(weeks=1)
    elif frequency == 'monthly':
        next_scan = datetime.now() + timedelta(days=30)
    else:
        return jsonify({'error': 'Invalid frequency'}), 400
    
    # Create scheduled scan
    scheduled = ScheduledScan(
        url=url,
        frequency=frequency,
        next_scan=next_scan,
        user_id=current_user.id,
        active=True
    )
    
    db.session.add(scheduled)
    db.session.commit()
    
    return jsonify({
        'message': 'Scan scheduled successfully',
        'scheduled_id': scheduled.id,
        'next_scan': next_scan.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/report/<int:scan_id>')
@login_required
def get_report(scan_id):
    """Download PDF report"""
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id and not current_user.is_admin:
        return "Unauthorized", 403
    
    if not scan.report_path or not os.path.exists(scan.report_path):
        return "Report not found", 404
    
    return send_file(scan.report_path, as_attachment=True)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)