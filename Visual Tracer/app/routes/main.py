from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user, login_required

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    return render_template('base.html', title='Network Tools')


@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('tools/traceroute.html', title='Dashboard')