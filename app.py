from flask import Flask, render_template, request, jsonify, send_from_directory, url_for
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from transformers import BertTokenizer, BertConfig, BertForSequenceClassification
from safetensors.torch import load_file
import torch
import os
from dotenv import load_dotenv
import whois  # For domain info (optional, install with `pip install python-whois`)
from model_utils import BERTPredictor

# Load environment variables
load_dotenv()

# Initialize Flask app with template directory pointing to Frontend folder
app = Flask(__name__, 
            template_folder='../Frontend',
            static_folder='../Frontend/static')

# Configure CORS
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "http://localhost:3000",
            "https://your-netlify-app.netlify.app"  # Replace with your Netlify domain
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    },
    r"/auth/*": {
        "origins": [
            "http://localhost:3000",
            "https://your-netlify-app.netlify.app"  # Replace with your Netlify domain
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    },
    r"/scan/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000"]},
    r"/report/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000"]}
})

# OAuth setup for Google login (replace with your credentials)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# Model directory and file paths
model_dir = os.path.join(os.path.dirname(__file__), 'trained_model')
vocab_path = os.path.join(model_dir, 'vocab.txt')
tokenizer_config_path = os.path.join(model_dir, 'tokenizer_config.json')
safetensors_path = os.path.join(model_dir, 'model.safetensors')
config_path = os.path.join(model_dir, 'config.json')

# Verify file existence
for path in [vocab_path, tokenizer_config_path, safetensors_path]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Required file not found: {path}")

# Load BERT tokenizer and model
if not os.path.exists(config_path):
    config = BertConfig.from_pretrained('bert-base-uncased', num_labels=2)  # Binary classification
else:
    config = BertConfig.from_pretrained(config_path)

tokenizer = BertTokenizer(
    vocab_file=vocab_path,
    do_lower_case=True,
    model_max_length=512,
    tokenizer_config_file=tokenizer_config_path
)
state_dict = load_file(safetensors_path)
model = BertForSequenceClassification(config)
model.load_state_dict(state_dict)
model.eval()

# Initialize BERT model
try:
    bert_predictor = BERTPredictor()
    print("BERT model loaded successfully")
except Exception as e:
    print(f"Error loading BERT model: {e}")
    bert_predictor = None

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/company')
def company():
    return render_template('company.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/non-technical')
def non_technical():
    # Optional: Pass sample ML data for non-technical users
    sample_log = "System scan completed with no issues detected."
    inputs = tokenizer(sample_log, return_tensors='pt', max_length=512, truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        prediction = torch.softmax(outputs.logits, dim=1).tolist()[0]
        vulnerability = 'Detected' if prediction[1] > 0.5 else 'Safe'
        confidence = max(prediction)
    return render_template('non-technical.html', vulnerability=vulnerability, confidence=confidence)

@app.route('/professional')
def professional():
    return render_template('professional.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/pentest-info')
def pentest_info():
    return render_template('pentest-info.html')

@app.route('/domain-info')
def domain_info():
    return render_template('domain-info.html')

# Static file routes
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/static/downloads/tools/<path:filename>')
def download_tool(filename):
    return send_from_directory('static/downloads/tools', filename)

# Authentication routes
@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    return jsonify({'message': 'Google login successful', 'user': user_info})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if username and password:  # Placeholder; add DB check
        return jsonify({'token': 'dummy_token', 'userType': data.get('userType', 'non-technical')})
    return jsonify({'message': 'Login failed'}), 401

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    return jsonify({'message': 'Registration successful'})  # Placeholder

# ML model routes
@app.route('/scan/analyze', methods=['POST'])
def analyze_scan():
    """
    Analyze scan logs for vulnerabilities
    """
    if not bert_predictor:
        return jsonify({'error': 'BERT model not initialized'}), 500
        
    try:
        log_text = request.json.get('log', '')
        if not log_text:
            return jsonify({'error': 'No log text provided'}), 400
            
        result = bert_predictor.predict(log_text)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/report/generate', methods=['POST'])
def generate_report():
    """
    Generate a security report with vulnerability analysis
    """
    if not bert_predictor:
        return jsonify({'error': 'BERT model not initialized'}), 500
        
    try:
        data = request.json.get('data', '')
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Analyze multiple sections if provided
        if isinstance(data, dict):
            results = {}
            for section, text in data.items():
                results[section] = bert_predictor.predict(text)
        else:
            results = bert_predictor.predict(data)
            
        return jsonify({'report': results})
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500

@app.route('/batch/analyze', methods=['POST'])
def batch_analyze():
    """
    Analyze multiple texts in one request
    """
    if not bert_predictor:
        return jsonify({'error': 'BERT model not initialized'}), 500
        
    try:
        texts = request.json.get('texts', [])
        if not texts or not isinstance(texts, list):
            return jsonify({'error': 'Invalid input: expected list of texts'}), 400
            
        results = bert_predictor.batch_predict(texts)
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': f'Batch analysis failed: {str(e)}'}), 500

# Domain info route (optional, using whois as an example)
@app.route('/api/domain-info', methods=['GET'])
def get_domain_info():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    try:
        w = whois.whois(domain)
        result = {
            'status': 'active' if w.status else 'inactive',
            'ip_address': 'N/A',  # Add IP lookup logic if needed
            'location': f"{w.city or 'N/A'}, {w.country or 'N/A'}",
            'registrar': w.registrar or 'N/A',
            'creation_date': w.creation_date[0].isoformat() if w.creation_date else 'N/A',
            'expiration_date': w.expiration_date[0].isoformat() if w.expiration_date else 'N/A',
            'nameservers': w.name_servers if w.name_servers else ['N/A']
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Could not retrieve domain information: {str(e)}'}), 500

# Contact form route
@app.route('/submit_form', methods=['POST'])
def submit_form():
    data = request.json
    return jsonify({'status': 'success'})  # Placeholder

# Serve static files from Frontend/static
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('../Frontend/static', filename)

# Serve shared files from Frontend/shared
@app.route('/shared/<path:filename>')
def serve_shared(filename):
    return send_from_directory('../Frontend/shared', filename)

if __name__ == '__main__':
    # Use environment variables with defaults for local development
    port = int(os.environ.get('PORT', 5000))
    if os.environ.get('ENVIRONMENT') == 'production':
        from waitress import serve
        serve(app, host='0.0.0.0', port=port)
    else:
        app.run(host='0.0.0.0', port=port, debug=True)