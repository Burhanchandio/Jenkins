from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from code_review import GeminiReview
import markdown
import subprocess
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Use a secure key in production

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
gemini_reviewer = GeminiReview(api_key=API_KEY)
users = {}
uploads = []

logging.basicConfig(level=logging.DEBUG)

def convert_to_html(review_text):
    html_content = markdown.markdown(review_text)
    html_template = f"""
    <html>
        <head>
            <title>Security Vulnerability Review</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    background-color: #f4f4f4;
                    padding: 20px;
                }}
                h1 {{
                    color: #333;
                    text-align: center;
                }}
                .content {{
                    background-color: #fff;
                    padding: 20px;
                    margin-top: 10px;
                    border-radius: 8px;
                }}
                .button-container {{
                    text-align: center;
                    margin-top: 20px;
                }}
                .dashboard-button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007BFF;
                    color: #fff;
                    text-decoration: none;
                    border-radius: 5px;
                }}
                .dashboard-button:hover {{
                    background-color: #0056b3;
                }}
            </style>
        </head>
        <body>
            <h1>Security Vulnerability Review</h1>
            <div class="content">
                {html_content}
            </div>
            <div class="button-container">
                <a href="{url_for('dashboard')}" class="dashboard-button">Go to Dashboard</a>
            </div>
        </body>
    </html>
    """
    return html_template

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        phone = request.form['phone']
        users[username] = {'email': email, 'password': password, 'phone': phone}
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    file_reports = []
    reviews_dir = 'reviews'
    bandit_reports_dir = 'bandit_reports'

    for filename in os.listdir(reviews_dir):
        # Expected name for the JSON report file
        json_report_filename = f"{filename}_bandit.json"
        bandit_json_path = os.path.join(bandit_reports_dir, json_report_filename)

        # Debug logging to check the file path
        logging.debug(f"Checking JSON report path: {bandit_json_path}")

        file_reports.append({
            'filename': filename,
            'review_path': os.path.join(reviews_dir, filename),
            'bandit_json_available': os.path.exists(bandit_json_path),
            'bandit_json_path': bandit_json_path
        })
    
    return render_template('dashboard.html', file_reports=file_reports)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        if file:
            code = file.read()  # Keeping it in binary form

            try:
                code_text = code.decode('utf-8', errors='ignore')
                logging.debug(f"Code text to be sent for review: {code_text}")

                # Generate the GeminiReview report and convert to HTML
                response = gemini_reviewer.send_code_for_review(code_text)
                
                if not response:
                    logging.error("No response received from Gemini API")
                    flash("An error occurred while processing the review. No response from API.")
                    return redirect(url_for('dashboard'))

                review_text = gemini_reviewer.parse_review_response(response)
                logging.debug(f"Review text received: {review_text}")

                html_review = convert_to_html(review_text)

                reviews_dir = 'reviews'
                if not os.path.exists(reviews_dir):
                    os.makedirs(reviews_dir)

                # Save the GeminiReview report as an HTML file
                output_file_name = f"{file.filename}_review.html"
                output_file_path = os.path.join(reviews_dir, output_file_name)
                with open(output_file_path, 'w') as output_file:
                    output_file.write(html_review)
                
                # Run Bandit analysis and save the report as JSON
                bandit_reports_dir = 'bandit_reports'
                if not os.path.exists(bandit_reports_dir):
                    os.makedirs(bandit_reports_dir)

                # Ensure consistent naming for the JSON report file
                json_report_filename = f"{file.filename}_review.html_bandit.json"
                bandit_json_path = os.path.join(bandit_reports_dir, json_report_filename)

                # Debug logging to verify where the JSON file will be saved
                logging.debug(f"Saving JSON report to: {bandit_json_path}")

                # Generate JSON Bandit report
                with open(bandit_json_path, 'w') as bandit_json_file:
                    subprocess.run(['bandit', '-r', '.', '-f', 'json'], stdout=bandit_json_file, text=True)

                session['latest_review_file'] = output_file_name

                return redirect(url_for('dashboard'))
            
            except Exception as e:
                logging.error(f"An error occurred: {e}")
                return f"An error occurred: {e}", 500
    
    return render_template('upload.html')

@app.route('/download_review/<filename>')
def download_review(filename):
    review_file_path = os.path.join('reviews', filename)
    if os.path.exists(review_file_path):
        return send_file(review_file_path, as_attachment=True)
    else:
        flash('Review file not found.')
        return redirect(url_for('dashboard'))

@app.route('/download_bandit_json/<filename>')
def download_bandit_json(filename):
    bandit_json_path = os.path.join('bandit_reports', f"{filename}_bandit.json")
    if os.path.exists(bandit_json_path):
        return send_file(bandit_json_path, as_attachment=True)
    else:
        flash('Bandit JSON report not found.')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('latest_review_file', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
