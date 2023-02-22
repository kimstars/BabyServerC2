import os
import subprocess
from flask import Blueprint, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
# from BabyServer import client
from BabyServer.core.dao import payload_dao

# Blueprint
osint_module = Blueprint('payload', __name__)


# Routes
# @payload.route("/osint/generate", methods=["POST"])
# @login_required
# def scan_username():
    