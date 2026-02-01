import json
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from socketdev import socketdev
import os

try:
    from dotenv import load_dotenv, set_key
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'change-this-secret')

SEVERITY_COLORS = {
    'critical': 'danger',
    'high': 'warning',
    'medium': 'warning',
    'middle': 'warning',
    'low': 'secondary',
}


class PackageForm(FlaskForm):
    package_inputs = TextAreaField('Package Identifiers (one per line)', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ApiTokenForm(FlaskForm):
    api_token = PasswordField('API Token', validators=[DataRequired()])
    submit = SubmitField('Save Token')

def save_token_to_env(token):
    """Save the API token to .env file"""
    if DOTENV_AVAILABLE:
        try:
            # Get the path to the .env file in the parent directory of app/
            env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
            set_key(env_path, 'SOCKET_SECURITY_API_KEY', token)
            return True
        except Exception as e:
            print(f"Warning: Could not save token to .env file: {e}")
            return False
    else:
        print("Warning: python-dotenv not available, token not saved to .env file")
        return False

def parse_package_inputs(text):
    """
    Parse package inputs supporting full PURL format.

    Supports:
    - Full PURL: pkg:ecosystem/name@version?qualifier=example
    - name@version (assumes Chrome extension)
    - name (assumes Chrome extension)
    """
    inputs = [line.strip() for line in text.splitlines() if line.strip()]
    purls = []
    for item in inputs:
        if item.startswith('pkg:'):
            # Already a full PURL, use as-is
            purls.append(item)
        elif '@' in item:
            # name@version format, assume Chrome extension
            name, version = item.split('@', 1)
            purl = f"pkg:chrome/{name}@{version}"
            purls.append(purl)
        else:
            # Just name, assume Chrome extension
            purl = f"pkg:chrome/{item}"
            purls.append(purl)
    return purls


@app.route('/', methods=['GET', 'POST'])
def index():
    # Check for API key in env or session
    api_token = os.environ.get('SOCKET_SECURITY_API_KEY')
    if not api_token:
        api_token = session.get('SOCKET_SECURITY_API_KEY')

    # If not set, prompt for API token
    if not api_token:
        form = ApiTokenForm()
        if form.validate_on_submit():
            token = form.api_token.data
            session['SOCKET_SECURITY_API_KEY'] = token
            # Save to .env file for future use
            save_token_to_env(token)
            return redirect(url_for('index'))
        return render_template('index.html', api_token_form=form, form=None, results=None, severity_colors=SEVERITY_COLORS)

    # Otherwise, show package form
    form = PackageForm()
    alert_rows = []
    prop_keys = set()
    # Default visible columns
    default_columns = ['name', 'version', 'size', 'severity', 'category', 'permissionType', 'alert_type']
    all_columns = ['name', 'version', 'type', 'size', 'author', 'severity', 'category', 'permissionType', 'file', 'alert_type']
    # Get user-selected columns from form or default
    selected_columns = request.form.getlist('columns') if request.method == 'POST' and 'columns' in request.form else default_columns
    # Get filter/search values
    filter_version = request.form.get('filter_version', '').strip()
    filter_category = request.form.get('filter_category', '').strip()
    filter_severity = request.form.get('filter_severity', '').strip()
    filter_permission = request.form.get('filter_permission', '').strip()
    search_name = request.form.get('search_name', '').strip()

    if form.validate_on_submit() or (request.method == 'POST' and 'columns' in request.form):
        package_inputs = form.package_inputs.data if form.validate_on_submit() else request.form.get('package_inputs', '')
        purls = parse_package_inputs(package_inputs)
        components = [{"purl": p} for p in purls]
        try:
            sdk = socketdev(token=api_token)
            response = sdk.purl.post(license=False, components=components, purlErrors="true", alerts="true")
            results_raw = response.get('results') if isinstance(response, dict) else response
            if results_raw is None:
                results_raw = []
            for item in results_raw:
                if isinstance(item, dict) and item.get('_type') == 'purlError':
                    alert_rows.append({
                        'error': item['value']['error'],
                        'inputPurl': item['value']['inputPurl']
                    })
                elif isinstance(item, dict) and 'alerts' in item and item['alerts']:
                    for alert in item['alerts']:
                        row = {
                            'name': item.get('name', '-'),
                            'version': item.get('version', '-'),
                            'type': item.get('type', '-'),
                            'size': item.get('size', '-'),
                            'author': ', '.join(item.get('author', [])) if item.get('author') else '-',
                            'severity': alert.get('severity', '-'),
                            'category': alert.get('category', '-'),
                            'permissionType': alert.get('props', {}).get('permissionType', '-') if alert.get('props') else '-',
                            'props': alert.get('props', {}),
                            'file': alert.get('file', '-'),
                            'alert_type': alert.get('type', '-'),
                            'error': None
                        }
                        if alert.get('props'):
                            prop_keys.update(alert['props'].keys())
                        alert_rows.append(row)
                elif isinstance(item, dict):
                    alert_rows.append({
                        'name': item.get('name', '-'),
                        'version': item.get('version', '-'),
                        'type': item.get('type', '-'),
                        'size': item.get('size', '-'),
                        'author': ', '.join(item.get('author', [])) if item.get('author') else '-',
                        'severity': '-',
                        'category': '-',
                        'permissionType': '-',
                        'props': {},
                        'file': '-',
                        'alert_type': '-',
                        'error': None
                    })
        except Exception as e:
            flash(f"Error: {e}", 'danger')
    prop_keys = sorted(prop_keys)
    # Filtering
    def row_matches(row):
        if filter_version and filter_version.lower() not in str(row.get('version', '')).lower():
            return False
        if filter_category and filter_category.lower() not in str(row.get('category', '')).lower():
            return False
        if filter_severity and filter_severity.lower() not in str(row.get('severity', '')).lower():
            return False
        if filter_permission and filter_permission.lower() not in str(row.get('permissionType', '')).lower():
            return False
        if search_name and search_name.lower() not in str(row.get('name', '')).lower():
            return False
        return True
    filtered_rows = [row for row in alert_rows if row_matches(row)]
    return render_template(
        'index.html',
        api_token_form=None,
        form=form,
        alert_rows=filtered_rows,
        prop_keys=prop_keys,
        severity_colors=SEVERITY_COLORS,
        all_columns=all_columns,
        selected_columns=selected_columns,
        filter_version=filter_version,
        filter_category=filter_category,
        filter_severity=filter_severity,
        filter_permission=filter_permission,
        search_name=search_name
    )

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=81)
