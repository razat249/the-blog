#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import webapp2
import os
import jinja2
from google.appengine.ext import db
import json
from google.appengine.api import memcache
import time
import logging
import cgi
import hashlib
import hmac
import string
import random

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)



######################################    Blog Stuff   ##########################################
#################################################################################################

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def data_query(self):
		arts = db.GqlQuery("SELECT * FROM  Art ORDER BY created DESC LIMIT 10")
		return list(arts)


class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)


class MainHandler(Handler):
	def render_form(self, title="", art="", error="" ):
		self.render("form.html",title = title, art = art , error = error)

	def get(self):
		self.render_form()

	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(title = title , art = art)
			a.put()
			memcache.flush_all()
			i = a.key().id()
			self.redirect("/blog/%s"%str(i))
		else:
			error = "We need both a title and some artwork"
			self.render_form(title , art, error)

class PermalinkHandler(Handler):
	def render_permalink(self, post_id ):
		p = Art.get_by_id(post_id)
		if not p:
			self.error(404)
			return
		self.render("permalink.html", p = p)
	def get(self,post_id):
		post_id = int(post_id)
		self.render_permalink(post_id)

begin_time = 0

class BlogHandler(Handler):
	def render_front(self, title="", art="", error=""):
		key = "top"
		arts = memcache.get(key)
		if arts == None:
			global begin_time
			begin_time = time.time()
			time.sleep(0.1)
			logging.error("DB QUERY")
			arts = self.data_query()
			memcache.set(key,arts)
		time.sleep(0.1)
		current_time = time.time()
		self.render("front.html", arts = arts,t = int(current_time - begin_time) )

	def get(self):
		self.render_front()

class JsonBlogHandler(Handler):
	def get(self):
		self.formate = 'json'
		arts = self.data_query()
		json_list = []
		for art in arts:
			json_file = {"subject":art.title,"content":art.art}
			json_list.append(json_file)
		self.response.headers['content-type'] = "application/json; charset=utf-8"
		self.response.out.write(json.dumps(json_list))

class JsonPermalinkHandler(Handler):
	def get(self,json_id):
		self.formate = 'json'
		d = Art.get_by_id(int(json_id))
		json_file = json.dumps({"subject":d.title,"content":d.art})
		self.response.headers['content-type'] = "application/json; charset=utf-8"
		self.response.out.write(json_file)

class FlushHandler(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')




############################################   Signup Stuff   ##################################################
################################################################################################################

def valid_username(username):
	USER_a = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	if USER_a.match(username):
		return ""
	return "This is not valid username"

def valid_password(username):
	USER_b = re.compile(r"^.{3,20}$")
	if USER_b.match(username):
		return ""
	return "This is not a valid password"

def valid_email(username):
	USER_c = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	if USER_c.match(username):
		return ""
	return "This is not a valid email"

def confirm_pass(p1,p2):
	if p1 == p2:
		return ""
	return "Your password didn't matched"

class Data(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

# password hashing stuff
def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s'%(h,salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)


# cookie hashing stuff
SECRET = "razat"

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return '%s|%s' % (s,hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val


class SignupHandler(Handler):
	def render_signup(self,username = "" , uerror = "" , perror = "" , vperror = "", eerror = ""):
		self.render("signup.html", username = username , uerror = uerror , perror = perror , vperror = vperror , eerror = eerror )

	def get(self):
		self.render_signup()

	def post(self):
		#get userdata
		username = self.request.get("username")	
		pcode = self.request.get("password")
		vcode = self.request.get("vp")
		cemail = self.request.get("email")

    	#filtering
		user = cgi.escape(valid_username(username),quote=True)
		passwd = cgi.escape(valid_password(pcode),quote=True)
		cpass = cgi.escape(confirm_pass(pcode,vcode),quote=True)
		email = cgi.escape(valid_email(cemail),quote=True)
		d = {"username":user,"uerror":"","perror":passwd,"vperror":cpass,"cemail":cemail,"eerror":email}

		if not (username and pcode and (pcode == vcode)):
			self.render_signup(username = user ,perror = passwd, vperror =cpass, eerror = email)
		else:
			password = make_pw_hash(username,pcode)
			d = Data(username=username,password = password)
			d.put()
			user_id = d.key().id()


			#cookies stuff
			cvalue = make_secure_val(str(user_id))	
			self.response.headers.add_header('set-cookie', 'user_id=%s' % cvalue)
			time.sleep(0.1)
			red = "/blog/welcome"
			self.redirect(red)

class WelcomeHandler(Handler):
	def get(self):
		user_id = check_secure_val(self.request.cookies.get('user_id'))
		if user_id:
			data = db.GqlQuery("SELECT * FROM Data ORDER BY created DESC")
			for d in data:
				if int(d.key().id()) == int(user_id):
					self.response.write("Welcome,"+d.username)
		else:
			self.redirect("/blog")

class LoginHandler(Handler):
	def render_login(self, username = ""):
		self.render("signin.html", username = username )

	def get(self):
		self.render_login()

	def post(self):
		user = self.request.get("username")
		passwd = self.request.get("password")
		data = db.GqlQuery("SELECT * FROM Data ORDER BY created DESC")
		for d in data:
			x = valid_pw(user,passwd,d.password)
			if d.username == user and x:
				user_id = d.key().id()
				cvalue = make_secure_val(str(user_id))
				self.response.headers.add_header('set-cookie', 'user_id=%s' % cvalue)
				self.redirect("/blog/welcome")
				break
			
class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('set-cookie', 'user_id=%s' % '')
		self.redirect("/blog")


app = webapp2.WSGIApplication([

], debug=True)


app = webapp2.WSGIApplication([('/blog/newpost/?', MainHandler),
								('/blog/?',BlogHandler),
								('/blog/([0-9]+)/?',PermalinkHandler),
								('/blog/?.json',JsonBlogHandler),
								('/blog/([0-9]+).json',JsonPermalinkHandler),
								('/blog/flush/?',FlushHandler),
							    ('/blog/signup/?', SignupHandler),
								('/blog/welcome/?', WelcomeHandler),
								('/blog/login/?',LoginHandler),
								('/blog/logout/?',LogoutHandler)
								], debug=True)