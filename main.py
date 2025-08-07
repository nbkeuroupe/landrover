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
    "3531540982734612": {"expiry": "1126", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
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
    """
    Execute a real blockchain transaction. The transaction will fail if
    production environment variables are not correctly configured.
    """
    if payout_type == "USDT-ERC20":
        logging.info("Attempting real USDT-ERC20 transaction.")
        return send_erc20_payout(
            ERC20_PRIVATE_KEY,
            wallet_address,
            amount,
            USDT_ERC20_CONTRACT,
            ETHEREUM_RPC
        )
    elif payout_type == "USDT-TRC20":
        logging.info("Attempting real USDT-TRC20 transaction.")
        return send_trc20_payout(
            TRC20_PRIVATE_KEY,
            wallet_address,
            amount,
            USDT_TRC20_CONTRACT,
            TRON_NETWORK
        )

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


# --- Flask Routes ---

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
        return render_template('change_password.html', success="Password changed successfully.")
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    transactions = get_transactions()
    return render_template('dashboard.html', transactions=transactions)

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    config = load_config()
    protocols = sorted(list(PROTOCOLS.keys()))
    if request.method == 'POST':
        protocol = request.form.get('protocol')
        session['protocol'] = protocol
        session['selected_protocol_code'] = next((code for name, code in PROTOCOLS.items() if name == protocol), None)
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=protocols, config=config)

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if 'protocol' not in session:
        flash("Please select a protocol first.")
        return redirect(url_for('protocol'))
    
    if request.method == 'POST':
        amount = request.form.get('amount')
        payout_type = request.form.get('payout_type')
        wallet_address = request.form.get('wallet_address')

        if not amount or not payout_type or not wallet_address:
            flash("All fields are required.")
            return redirect(url_for('amount'))

        session['payout_data'] = {
            'amount': amount,
            'payout_type': payout_type,
            'wallet_address': wallet_address
        }
        return redirect(url_for('payment'))
    
    config = load_config()
    return render_template('amount.html', config=config)

@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if 'payout_data' not in session:
        flash("Please enter transaction details first.")
        return redirect(url_for('amount'))

    if request.method == 'POST':
        card_number = request.form.get('card_number').replace(' ', '')
        expiry = request.form.get('expiry')
        cvv = request.form.get('cvv')
        auth_code = request.form.get('auth_code')

        # Check for expired cards
        current_year = datetime.now().year % 100
        current_month = datetime.now().month
        
        try:
            exp_month = int(expiry[:2])
            exp_year = int(expiry[2:])
        except (ValueError, IndexError):
            flash(FIELD_39_RESPONSES.get('54'))
            return render_template('payment.html')

        if exp_year < current_year or (exp_year == current_year and exp_month < current_month):
            flash(FIELD_39_RESPONSES.get('54'))
            return render_template('payment.html')
        
        card_info = DUMMY_CARDS.get(card_number)

        # Check terminal protocol
        protocol_name = session.get('protocol')
        protocol_type = card_info['type'] if card_info else 'unknown'
        if protocol_name is None or not protocol_name.startswith(protocol_type.split('.')[0]):
            flash(FIELD_39_RESPONSES.get('92'))
            return render_template('payment.html')

        # Dummy gateway logic
        if card_info and card_info['expiry'] == expiry and card_info['cvv'] == cvv:
            if card_info['auth'] == auth_code:
                # Payment successful, proceed to payout
                flash("Card payment authorized successfully!", "success")
                session['payment_authorized'] = True
                return redirect(url_for('payout'))
            else:
                flash("Invalid authorization code.")
        else:
            flash("Invalid card number, expiry, or CVV.")
        
    return render_template('payment.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if not session.get('payment_authorized') or 'payout_data' not in session:
        flash("Payment not authorized or transaction data missing.")
        return redirect(url_for('protocol'))

    if request.method == 'POST':
        totp_token = request.form.get('totp_token')
        if not verify_totp(totp_token):
            flash("Invalid or expired TOTP token.")
            return render_template('payout.html')
        
        payout_data = session['payout_data']
        amount = payout_data['amount']
        payout_type = payout_data['payout_type']
        wallet_address = payout_data['wallet_address']
        
        txn_id = f"txn_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]}"
        
        # This function will now attempt a real transaction.
        tx_hash = execute_real_blockchain_payout(amount, payout_type, wallet_address)
        
        if tx_hash:
            transaction_data = {
                'txn_id': txn_id,
                'tx_hash': tx_hash,
                'amount': amount,
                'payout_type': payout_type,
                'wallet_address': wallet_address,
                'timestamp': datetime.now().isoformat(),
                'status': 'BROADCASTING',
                'confirmations': 0,
                'block_number': None,
            }
            save_transaction(transaction_data)
            
            # Start a background thread to track confirmation
            threading.Thread(target=track_confirmation, args=(txn_id, tx_hash, payout_type), daemon=True).start()
            
            session.pop('payment_authorized')
            session.pop('payout_data')
            session['txn_id'] = txn_id
            return redirect(url_for('receipt'))
        else:
            flash("Failed to initiate blockchain transaction. Please ensure all required environment variables and keys are configured correctly.")
            return render_template('payout.html')

    # For GET request, display the payout page
    return render_template('payout.html')

@app.route('/receipt')
@login_required
def receipt():
    txn_id = session.get('txn_id')
    if not txn_id:
        flash("No transaction receipt found.")
        return redirect(url_for('dashboard'))

    transactions = get_transactions()
    receipt_data = next((t for t in transactions if t['txn_id'] == txn_id), None)
    
    if receipt_data:
        return render_template('receipt.html', receipt=receipt_data)
    
    flash("Transaction receipt not found.")
    return redirect(url_for('dashboard'))

# ISO8583 server startup
iso8583_server_thread()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
