
from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
from main import login_required, check_password

def create_admin_routes(app):
    @app.route('/admin')
    @login_required
    def admin_panel():
        config = {}
        if os.path.exists('config.json'):
            with open('config.json') as f:
                config = json.load(f)
        return render_template('admin.html', config=config)
    
    @app.route('/admin/update-wallets', methods=['POST'])
    @login_required
    def update_wallets():
        erc20_wallet = request.form.get('erc20_wallet')
        trc20_wallet = request.form.get('trc20_wallet')
        
        config = {}
        if os.path.exists('config.json'):
            with open('config.json') as f:
                config = json.load(f)
        
        config['erc20_wallet'] = erc20_wallet
        config['trc20_wallet'] = trc20_wallet
        
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        flash("Wallet addresses updated successfully!")
        return redirect(url_for('admin_panel'))

# Import this in main.py to register routes
