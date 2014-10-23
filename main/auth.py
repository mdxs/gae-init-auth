# coding: utf-8

from base64 import b64encode
import functools
import re

from flask.ext import login
from flask.ext import wtf
from flask.ext.oauthlib import client as oauth
from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.ext import ndb
from werkzeug import urls
import flask
import unidecode
import wtforms


import cache
import config
import model
import task
import util

from main import app

_signals = flask.signals.Namespace()

###############################################################################
# Flask Login
###############################################################################
login_manager = login.LoginManager()


class AnonymousUser(login.AnonymousUserMixin):
  id = 0
  admin = False
  name = 'Anonymous'
  user_db = None

  def key(self):
    return None

  def has_permission(self, permission):
    return False

login_manager.anonymous_user = AnonymousUser


class FlaskUser(AnonymousUser):
  def __init__(self, user_db):
    self.user_db = user_db
    self.id = user_db.key.id()
    self.name = user_db.name
    self.admin = user_db.admin

  def key(self):
    return self.user_db.key.urlsafe()

  def get_id(self):
    return self.user_db.key.urlsafe()

  def is_authenticated(self):
    return True

  def is_active(self):
    return self.user_db.active

  def is_anonymous(self):
    return False

  def has_permission(self, permission):
    return self.user_db.has_permission(permission)


@login_manager.user_loader
def load_user(key):
  user_db = ndb.Key(urlsafe=key).get()
  if user_db:
    return FlaskUser(user_db)
  return None


login_manager.init_app(app)


def current_user_id():
  return login.current_user.id


def current_user_key():
  return login.current_user.user_db.key if login.current_user.user_db else None


def current_user_db():
  return login.current_user.user_db


def is_logged_in():
  return login.current_user.id != 0


###############################################################################
# Decorators
###############################################################################
def login_required(f):
  decorator_order_guard(f, 'auth.login_required')

  @functools.wraps(f)
  def decorated_function(*args, **kws):
    if is_logged_in():
      return f(*args, **kws)
    if flask.request.path.startswith('/_s/'):
      return flask.abort(401)
    return flask.redirect(flask.url_for('signin', next=flask.request.url))
  return decorated_function


def admin_required(f):
  decorator_order_guard(f, 'auth.admin_required')

  @functools.wraps(f)
  def decorated_function(*args, **kws):
    if is_logged_in() and current_user_db().admin:
      return f(*args, **kws)
    if not is_logged_in() and flask.request.path.startswith('/_s/'):
      return flask.abort(401)
    if not is_logged_in():
      return flask.redirect(flask.url_for('signin', next=flask.request.url))
    return flask.abort(403)
  return decorated_function


permission_registered = _signals.signal('permission-registered')


def permission_required(permission=None, methods=None):
  def permission_decorator(f):
    decorator_order_guard(f, 'auth.permission_required')

    # default to decorated function name as permission
    perm = permission or f.func_name
    meths = [m.upper() for m in methods] if methods else None

    permission_registered.send(f, permission=perm)

    @functools.wraps(f)
    def decorated_function(*args, **kws):
      if meths and flask.request.method.upper() not in meths:
        return f(*args, **kws)
      if is_logged_in() and current_user_db().has_permission(perm):
        return f(*args, **kws)
      if not is_logged_in():
        if flask.request.path.startswith('/_s/'):
          return flask.abort(401)
        return flask.redirect(flask.url_for('signin', next=flask.request.url))
      return flask.abort(403)
    return decorated_function
  return permission_decorator


###############################################################################
# Sign in/up stuff
###############################################################################
def create_oauth_app(service_config, name):
  upper_name = name.upper()
  app.config[upper_name] = service_config
  service_oauth = oauth.OAuth()
  service_app = service_oauth.remote_app(name, app_key=upper_name)
  service_oauth.init_app(app)
  return service_app


class SignInForm(wtf.Form):
  email = wtforms.StringField(
      'Email',
      [wtforms.validators.required()],
      filters=[util.email_filter],
    )
  password = wtforms.StringField(
      'Password',
      [wtforms.validators.required()],
    )
  remember = wtforms.BooleanField(
      'Keep me signed in',
      [wtforms.validators.optional()],
    )
  recaptcha = wtf.RecaptchaField('Are you human?')
  next_url = wtforms.HiddenField()


class SignUpForm(wtf.Form):
  email = wtforms.StringField(
      'Email',
      [wtforms.validators.required(), wtforms.validators.email()],
      filters=[util.email_filter],
    )
  recaptcha = wtf.RecaptchaField('Are you human?')


@app.route('/signup/', methods=['GET', 'POST'], endpoint='signup')
@app.route('/signin/', methods=['GET', 'POST'], endpoint='signin')
def auth():
  auth_type = 'open'
  if config.CONFIG_DB.has_email_authentication:
    auth_type = 'signin'
    if flask.url_for('signup') in flask.request.path:
      auth_type = 'signup'

  next_url = util.get_next_url()

  bitbucket_signin_url = url_for_signin('bitbucket', next_url)
  dropbox_signin_url = url_for_signin('dropbox', next_url)
  facebook_signin_url = url_for_signin('facebook', next_url)
  facebook_signin_url = url_for_signin('facebook', next_url)
  github_signin_url = url_for_signin('github', next_url)
  google_signin_url = url_for_signin('google', next_url)
  instgram_signin_url = url_for_signin('instagram', next_url)
  linkedin_signin_url = url_for_signin('linkedin', next_url)
  microsoft_signin_url = url_for_signin('microsoft', next_url)
  reddit_signin_url = url_for_signin('reddit', next_url)
  stackoverflow_signin_url = url_for_signin('stackoverflow', next_url)
  twitter_signin_url = url_for_signin('twitter', next_url)
  vk_signin_url = url_for_signin('vk', next_url)
  yahoo_signin_url = url_for_signin('yahoo', next_url)

  form = None
  hide_recaptcha = cache.get_auth_attempt() < config.RECAPTCHA_LIMIT

  # --------------
  # Sign in stuff
  # --------------
  if auth_type == 'signin':
    form = SignInForm()
    if hide_recaptcha or not config.CONFIG_DB.has_recaptcha:
      del form.recaptcha
    save_request_params()
    if form.validate_on_submit():
      result = retrieve_user_from_email(form.email.data, form.password.data)
      if result:
        cache.reset_auth_attempt()
        return signin_user_db(result)
      if result is None:
        form.email.errors.append('Email or Password do not match')
      if result is False:
        return flask.redirect(flask.url_for('welcome'))
    if not form.errors:
      form.next_url.data = next_url

  # --------------
  # Sign up stuff
  # --------------
  if auth_type == 'signup':
    form = SignUpForm()
    if hide_recaptcha or not config.CONFIG_DB.has_recaptcha:
      del form.recaptcha
    save_request_params()
    if form.validate_on_submit():
      user_db = model.User.get_by('email', form.email.data)
      if user_db:
        form.email.errors.append('This email is already taken.')

      if not form.errors:
        user_db = create_user_db(
            None,
            util.create_name_from_email(form.email.data),
            form.email.data,
            form.email.data,
          )
        user_db.put()
        task.activate_user_notification(user_db)
        cache.bump_auth_attempt()
        return flask.redirect(flask.url_for('welcome'))

  if form and form.errors:
    cache.bump_auth_attempt()

  return flask.render_template(
      'auth/auth.html',
      title='Sign up' if auth_type == 'signup' else 'Sign in',
      html_class='auth %s' % auth_type,
      bitbucket_signin_url=bitbucket_signin_url,
      dropbox_signin_url=dropbox_signin_url,
      facebook_signin_url=facebook_signin_url,
      github_signin_url=github_signin_url,
      google_signin_url=google_signin_url,
      instagram_signin_url=instgram_signin_url,
      linkedin_signin_url=linkedin_signin_url,
      microsoft_signin_url=microsoft_signin_url,
      reddit_signin_url=reddit_signin_url,
      stackoverflow_signin_url=stackoverflow_signin_url,
      twitter_signin_url=twitter_signin_url,
      vk_signin_url=vk_signin_url,
      yahoo_signin_url=yahoo_signin_url,
      next_url=next_url,
      form=form,
      auth_type=auth_type,
    )


@app.route('/signout/')
def signout():
  login.logout_user()
  flask.flash('You have been signed out.', category='success')
  return flask.redirect(util.param('next') or flask.url_for('signin'))


###############################################################################
# Google
###############################################################################
@app.route('/signin/google/')
def signin_google():
  save_request_params()
  google_url = users.create_login_url(flask.url_for('google_authorized'))
  return flask.redirect(google_url)


@app.route('/_s/callback/google/authorized/')
def google_authorized():
  google_user = users.get_current_user()
  if google_user is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  user_db = retrieve_user_from_google(google_user)
  return signin_user_db(user_db)


def retrieve_user_from_google(google_user):
  auth_id = 'federated_%s' % google_user.user_id()
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    if not user_db.admin and users.is_current_user_admin():
      user_db.admin = True
      user_db.put()
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=util.create_name_from_email(google_user.email()),
      username=google_user.email(),
      email=google_user.email(),
      verified=True,
      admin=users.is_current_user_admin(),
    )


###############################################################################
# Twitter
###############################################################################
twitter_config = dict(
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    consumer_key=config.CONFIG_DB.twitter_consumer_key,
    consumer_secret=config.CONFIG_DB.twitter_consumer_secret,
  )

twitter = create_oauth_app(twitter_config, 'twitter')


@app.route('/_s/callback/twitter/oauth-authorized/')
def twitter_authorized():
  response = twitter.authorized_response()
  if response is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )
  user_db = retrieve_user_from_twitter(response)
  return signin_user_db(user_db)


@twitter.tokengetter
def get_twitter_token():
  return flask.session.get('oauth_token')


@app.route('/signin/twitter/')
def signin_twitter():
  try:
    return signin_oauth(twitter)
  except:
    flask.flash(
        'Something went wrong with Twitter sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))


def retrieve_user_from_twitter(response):
  auth_id = 'twitter_%s' % response['user_id']
  user_db = model.User.get_by('auth_ids', auth_id)
  return user_db or create_user_db(
      auth_id=auth_id,
      name=response['screen_name'],
      username=response['screen_name'],
    )


###############################################################################
# Facebook
###############################################################################
facebook_config = dict(
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=config.CONFIG_DB.facebook_app_id,
    consumer_secret=config.CONFIG_DB.facebook_app_secret,
    request_token_params={'scope': 'email'},
  )

facebook = create_oauth_app(facebook_config, 'facebook')


@app.route('/_s/callback/facebook/oauth-authorized/')
def facebook_authorized():
  response = facebook.authorized_response()
  if response is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (response['access_token'], '')
  me = facebook.get('/me')
  user_db = retrieve_user_from_facebook(me.data)
  return signin_user_db(user_db)


@facebook.tokengetter
def get_facebook_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/facebook/')
def signin_facebook():
  return signin_oauth(facebook)


def retrieve_user_from_facebook(response):
  auth_id = 'facebook_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  return user_db or create_user_db(
      auth_id=auth_id,
      name=response['name'],
      username=response.get('username', response['name']),
      email=response.get('email', ''),
      verified=bool(response.get('email', '')),
    )


###############################################################################
# Bitbucket
###############################################################################
bitbucket_config = dict(
    base_url='https://api.bitbucket.org/1.0/',
    request_token_url='https://bitbucket.org/api/1.0/oauth/request_token',
    access_token_url='https://bitbucket.org/api/1.0/oauth/access_token',
    authorize_url='https://bitbucket.org/api/1.0/oauth/authenticate',
    consumer_key=config.CONFIG_DB.bitbucket_key,
    consumer_secret=config.CONFIG_DB.bitbucket_secret,
  )

bitbucket = create_oauth_app(bitbucket_config, 'bitbucket')


@app.route('/_s/callback/bitbucket/oauth-authorized/')
def bitbucket_authorized():
  response = bitbucket.authorized_response()
  if response is None:
    return 'Access denied'

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )
  me = bitbucket.get('user')
  user_db = retrieve_user_from_bitbucket(me.data['user'])
  return signin_user_db(user_db)


@bitbucket.tokengetter
def get_bitbucket_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/bitbucket/')
def signin_bitbucket():
  return signin_oauth(bitbucket)


def retrieve_user_from_bitbucket(response):
  auth_id = 'bitbucket_%s' % response['username']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  if response['first_name'] or response['last_name']:
    name = ' '.join((response['first_name'], response['last_name'])).strip()
  else:
    name = response['username']
  emails = bitbucket.get('users/%s/emails' % response['username'])
  email = ''.join([e['email'] for e in emails.data if e['primary']][0:1])
  return create_user_db(
      auth_id=auth_id,
      name=name,
      username=response['username'],
      email=email,
      verified=bool(email),
    )


###############################################################################
# Dropbox
###############################################################################
dropbox_config = dict(
    base_url='https://www.dropbox.com/1/',
    request_token_params={},
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://api.dropbox.com/1/oauth2/token',
    authorize_url='https://www.dropbox.com/1/oauth2/authorize',
    consumer_key=model.Config.get_master_db().dropbox_app_key,
    consumer_secret=model.Config.get_master_db().dropbox_app_secret,
  )

dropbox = create_oauth_app(dropbox_config, 'dropbox')


@app.route('/_s/callback/dropbox/oauth-authorized/')
def dropbox_authorized():
  response = dropbox.authorized_response()
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['oauth_token'] = (response['access_token'], '')
  me = dropbox.get('account/info')
  user_db = retrieve_user_from_dropbox(me.data)
  return signin_user_db(user_db)


@dropbox.tokengetter
def get_dropbox_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/dropbox/')
def signin_dropbox():
  return signin_oauth(dropbox, 'https')


def retrieve_user_from_dropbox(response):
  auth_id = 'dropbox_%s' % response['uid']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response['display_name'],
      username=response['display_name'],
    )


###############################################################################
# GitHub
###############################################################################
github_config = dict(
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    consumer_key=config.CONFIG_DB.github_client_id,
    consumer_secret=config.CONFIG_DB.github_client_secret,
    request_token_params={'scope': 'user:email'},
  )

github = create_oauth_app(github_config, 'github')


@app.route('/_s/callback/github/oauth-authorized/')
def github_authorized():
  response = github.authorized_response()
  if response is None:
    return 'Access denied: error=%s' % flask.request.args['error']
  flask.session['oauth_token'] = (response['access_token'], '')
  me = github.get('user')
  user_db = retrieve_user_from_github(me.data)
  return signin_user_db(user_db)


@github.tokengetter
def get_github_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/github/')
def signin_github():
  return signin_oauth(github)


def retrieve_user_from_github(response):
  auth_id = 'github_%s' % str(response['id'])
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  return create_user_db(
      auth_id,
      response.get('name', response.get('login')),
      response.get('login'),
      response.get('email', ''),
      verified=bool(response.get('email', '')),
    )


###############################################################################
# Instagram
###############################################################################
instagram_config = dict(
    base_url='https://api.instagram.com/v1',
    request_token_url=None,
    access_token_url='https://api.instagram.com/oauth/access_token',
    access_token_method='POST',
    authorize_url='https://instagram.com/oauth/authorize/',
    consumer_key=model.Config.get_master_db().instagram_client_id,
    consumer_secret=model.Config.get_master_db().instagram_client_secret,
  )

instagram = create_oauth_app(instagram_config, 'instagram')


@app.route('/_s/callback/instagram/oauth-authorized/')
def instagram_authorized():
  response = instagram.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (response['access_token'], '')
  user_db = retrieve_user_from_instagram(response['user'])
  return signin_user_db(user_db)


@instagram.tokengetter
def get_instagram_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/instagram/')
def signin_instagram():
  return signin_oauth(instagram)


def retrieve_user_from_instagram(response):
  auth_id = 'instagram_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response.get('full_name', '').strip() or response.get('username'),
      username=response.get('username'),
    )


###############################################################################
# LinkedIn
###############################################################################
linkedin_config = dict(
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    access_token_method='POST',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
    consumer_key=config.CONFIG_DB.linkedin_api_key,
    consumer_secret=config.CONFIG_DB.linkedin_secret_key,
    request_token_params={
        'scope': 'r_basicprofile r_emailaddress',
        'state': util.uuid(),
      },
  )

linkedin = create_oauth_app(linkedin_config, 'linkedin')


@app.route('/_s/callback/linkedin/oauth-authorized/')
def linkedin_authorized():
  response = linkedin.authorized_response()
  if response is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['access_token'] = (response['access_token'], '')
  me = linkedin.get('people/~:(id,first-name,last-name,email-address)')
  user_db = retrieve_user_from_linkedin(me.data)
  return signin_user_db(user_db)


@linkedin.tokengetter
def get_linkedin_oauth_token():
  return flask.session.get('access_token')


@app.route('/signin/linkedin/')
def signin_linkedin():
  return signin_oauth(linkedin)


def retrieve_user_from_linkedin(response):
  auth_id = 'linkedin_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  names = [response.get('firstName', ''), response.get('lastName', '')]
  name = ' '.join(names).strip()
  email = response.get('emailAddress', '')
  return create_user_db(
      auth_id=auth_id,
      name=name,
      username=email or name,
      email=email,
      verified=bool(email),
    )


###############################################################################
# Reddit
###############################################################################
reddit_config = dict(
    base_url='https://oauth.reddit.com/api/v1/',
    request_token_url=None,
    access_token_url='https://ssl.reddit.com/api/v1/access_token',
    access_token_params={'grant_type': 'authorization_code'},
    access_token_method='POST',
    authorize_url='https://ssl.reddit.com/api/v1/authorize',
    consumer_key=model.Config.get_master_db().reddit_client_id,
    consumer_secret=model.Config.get_master_db().reddit_client_secret,
    request_token_params={'scope': 'identity', 'state': util.uuid()},
  )

reddit = create_oauth_app(reddit_config, 'reddit')


def reddit_handle_oauth2_response():
  access_args = {
      'code': flask.request.args.get('code'),
      'client_id': reddit.consumer_key,
      'redirect_uri': flask.session.get('%s_oauthredir' % reddit.name),
    }
  access_args.update(reddit.access_token_params)
  auth = 'Basic ' + b64encode(
      ('%s:%s' % (reddit.consumer_key, reddit.consumer_secret)).encode(
          'latin1')).strip().decode('latin1')
  response, content = reddit.http_request(
      reddit.expand_url(reddit.access_token_url),
      method=reddit.access_token_method,
      data=urls.url_encode(access_args),
      headers={
          'Authorization': auth,
          'User-Agent': config.USER_AGENT,
        },
    )
  data = oauth.parse_response(response, content)
  if response.code not in (200, 201):
    raise oauth.OAuthException(
        'Invalid response from %s' % reddit.name,
        type='invalid_response', data=data,
      )
  return data


reddit.handle_oauth2_response = reddit_handle_oauth2_response


@app.route('/_s/callback/reddit/oauth-authorized/')
def reddit_authorized():
  response = reddit.authorized_response()
  if response is None or flask.request.args.get('error'):
    return 'Access denied: error=%s' % (flask.request.args['error'])

  flask.session['oauth_token'] = (response['access_token'], '')
  me = reddit.request('me')
  user_db = retrieve_user_from_reddit(me.data)
  return signin_user_db(user_db)


@reddit.tokengetter
def get_reddit_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/reddit/')
def signin_reddit():
  return signin_oauth(reddit)


def retrieve_user_from_reddit(response):
  auth_id = 'reddit_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response['name'],
      username=response['name'],
    )


###############################################################################
# Stack Overflow (via Stack Exchange)
###############################################################################
stackoverflow_config = dict(
    base_url='https://api.stackexchange.com/2.2/',
    request_token_url=None,
    access_token_url='https://stackexchange.com/oauth/access_token',
    access_token_method='POST',
    authorize_url='https://stackexchange.com/oauth',
    consumer_key=config.CONFIG_DB.stackoverflow_client_id,
    consumer_secret=config.CONFIG_DB.stackoverflow_client_secret,
    request_token_params={},
  )

stackoverflow = create_oauth_app(stackoverflow_config, 'stackoverflow')


@app.route('/_s/callback/stackoverflow/oauth-authorized/')
def stackoverflow_authorized():
  response = stackoverflow.authorized_response()
  if response is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (response['access_token'], '')
  me = stackoverflow.get(
      '/me',
      data={
          'access_token': response['access_token'],
          'key': config.CONFIG_DB.stackoverflow_key,
          'site': 'stackoverflow',
        },
    )
  if not me.data.get('items') or not me.data['items'][0]:
    return 'Missing account details for Stack Overflow.'

  user_db = retrieve_user_from_stackoverflow(me.data['items'][0])
  return signin_user_db(user_db)


@stackoverflow.tokengetter
def get_stackoverflow_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/stackoverflow/')
def signin_stackoverflow():
  return signin_oauth(stackoverflow)


def retrieve_user_from_stackoverflow(response):
  auth_id = 'stackoverflow_%s' % response['user_id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  return create_user_db(
      auth_id=auth_id,
      name=response['display_name'],
      username=response['display_name'],
    )


###############################################################################
# VK
###############################################################################
vk_config = dict(
    base_url='https://api.vk.com/',
    request_token_url=None,
    access_token_url='https://oauth.vk.com/access_token',
    authorize_url='https://oauth.vk.com/authorize',
    consumer_key=model.Config.get_master_db().vk_app_id,
    consumer_secret=model.Config.get_master_db().vk_app_secret,
  )

vk = create_oauth_app(vk_config, 'vk')


@app.route('/_s/callback/vk/oauth-authorized/')
def vk_authorized():
  response = vk.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  access_token = response['access_token']
  flask.session['oauth_token'] = (access_token, '')
  me = vk.get(
      '/method/users.get',
      data={
          'access_token': access_token,
          'format': 'json',
        },
    )
  user_db = retrieve_user_from_vk(me.data['response'][0])
  return signin_user_db(user_db)


@vk.tokengetter
def get_vk_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/vk/')
def signin_vk():
  return signin_oauth(vk)


def retrieve_user_from_vk(response):
  auth_id = 'vk_%s' % response['uid']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  name = ' '.join((response['first_name'], response['last_name'])).strip()
  return create_user_db(
      auth_id=auth_id,
      name=name,
      username=name,
    )


###############################################################################
# Microsoft
###############################################################################
microsoft_config = dict(
    base_url='https://apis.live.net/v5.0/',
    request_token_url=None,
    access_token_url='https://login.live.com/oauth20_token.srf',
    access_token_method='POST',
    authorize_url='https://login.live.com/oauth20_authorize.srf',
    consumer_key=model.Config.get_master_db().microsoft_client_id,
    consumer_secret=model.Config.get_master_db().microsoft_client_secret,
    request_token_params={'scope': 'wl.emails'},
  )

microsoft = create_oauth_app(microsoft_config, 'microsoft')


@app.route('/_s/callback/microsoft/oauth-authorized/')
def microsoft_authorized():
  response = microsoft.authorized_response()
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['oauth_token'] = (response['access_token'], '')
  me = microsoft.get('me')
  if me.data.get('error', {}):
    return 'Unknown error: error:%s error_description:%s' % (
        me['error']['code'],
        me['error']['message'],
      )
  user_db = retrieve_user_from_microsoft(me.data)
  return signin_user_db(user_db)


@microsoft.tokengetter
def get_microsoft_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/microsoft/')
def signin_microsoft():
  return signin_oauth(microsoft)


def retrieve_user_from_microsoft(response):
  auth_id = 'microsoft_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  email = response['emails']['preferred'] or response['emails']['account']
  return create_user_db(
      auth_id,
      response.get('name', ''),
      email,
      email,
      verified=bool(email),
    )


###############################################################################
# Yahoo!
###############################################################################
yahoo_config = dict(
    base_url='https://query.yahooapis.com/',
    request_token_url='https://api.login.yahoo.com/oauth/v2/get_request_token',
    access_token_url='https://api.login.yahoo.com/oauth/v2/get_token',
    authorize_url='https://api.login.yahoo.com/oauth/v2/request_auth',
    consumer_key=model.Config.get_master_db().yahoo_consumer_key,
    consumer_secret=model.Config.get_master_db().yahoo_consumer_secret,
  )

yahoo = create_oauth_app(yahoo_config, 'yahoo')


@app.route('/_s/callback/yahoo/oauth-authorized/')
def yahoo_authorized():
  response = yahoo.authorized_response()
  if response is None:
    flask.flash('You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )

  fields = 'guid, emails, familyName, givenName, nickname'
  me = yahoo.get(
      '/v1/yql',
      data={
          'format': 'json',
          'q': 'select %s from social.profile where guid = me;' % fields,
          'realm': 'yahooapis.com',
        },
    )
  user_db = retrieve_user_from_yahoo(me.data['query']['results']['profile'])
  return signin_user_db(user_db)


@yahoo.tokengetter
def get_yahoo_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/yahoo/')
def signin_yahoo():
  try:
    return signin_oauth(yahoo)
  except:
    flask.flash(
        'Something went wrong with Yahoo! sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))


def retrieve_user_from_yahoo(response):
  auth_id = 'yahoo_%s' % response['guid']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  names = [response.get('givenName', ''), response.get('familyName', '')]
  emails = response.get('emails', {})
  if not isinstance(emails, list):
    emails = [emails]
  emails = [e for e in emails if 'handle' in e]
  emails.sort(key=lambda e: e.get('primary', False))
  email = emails[0]['handle'] if emails else ''
  return create_user_db(
      auth_id=auth_id,
      name=' '.join(names).strip() or response['nickname'],
      username=response['nickname'],
      email=email,
      verified=bool(email),
    )


###############################################################################
# Helpers
###############################################################################
def decorator_order_guard(f, decorator_name):
  if f in app.view_functions.values():
    raise SyntaxError(
        'Do not use %s above app.route decorators as it would not be checked. '
        'Instead move the line below the app.route lines.' % decorator_name
      )


def create_user_db(auth_id, name, username, email='', verified=False, **props):
  email = email.lower() if email else ''
  if verified and email:
    user_dbs, user_cr = model.User.get_dbs(email=email, verified=True, limit=2)
    if len(user_dbs) == 1:
      user_db = user_dbs[0]
      user_db.auth_ids.append(auth_id)
      user_db.put()
      task.new_user_notification(user_db)
      return user_db

  if isinstance(username, str):
    username = username.decode('utf-8')
  username = unidecode.unidecode(username.split('@')[0].lower()).strip()
  username = re.sub(r'[\W_]+', '.', username)
  new_username = username
  n = 1
  while not model.User.is_username_available(new_username):
    new_username = '%s%d' % (username, n)
    n += 1

  user_db = model.User(
      name=name,
      email=email,
      username=new_username,
      auth_ids=[auth_id] if auth_id else [],
      verified=verified,
      token=util.uuid(),
      **props
    )
  user_db.put()
  task.new_user_notification(user_db)
  return user_db


def save_request_params():
  flask.session['auth-params'] = {
      'next': util.get_next_url(),
      'remember': util.param('remember', bool),
    }


def signin_oauth(oauth_app, scheme='http'):
  flask.session.pop('oauth_token', None)
  save_request_params()
  return oauth_app.authorize(callback=flask.url_for(
      '%s_authorized' % oauth_app.name, _external=True, _scheme=scheme
    ))


def url_for_signin(service_name, next_url):
  return flask.url_for('signin_%s' % service_name, next=next_url)


@ndb.toplevel
def signin_user_db(user_db):
  if not user_db:
    return flask.redirect(flask.url_for('signin'))
  flask_user_db = FlaskUser(user_db)
  auth_params = flask.session.get('auth-params', {
      'next': flask.url_for('welcome'),
      'remember': False,
    })
  flask.session.pop('auth-params', None)
  if login.login_user(flask_user_db, remember=auth_params['remember']):
    user_db.put_async()
    flask.flash('Hello %s, welcome to %s.' % (
        user_db.name, config.CONFIG_DB.brand_name,
      ), category='success')
    return flask.redirect(util.get_next_url(auth_params['next']))
  flask.flash('Sorry, but you could not sign in.', category='danger')
  return flask.redirect(flask.url_for('signin'))


def retrieve_user_from_email(email, password):
  user_dbs, user_cursor = model.User.get_dbs(email=email, active=True, limit=2)
  if not user_dbs:
    return None
  if len(user_dbs) > 1:
    flask.flash('''We are sorry but it looks like there is a conflict with
        your account. Our support team is already informed and we will get
        back to you as soon as possible.''', category='danger')
    task.email_conflict_notification(email)
    return False

  user_db = user_dbs[0]
  if user_db.password_hash == util.password_hash(user_db, password):
    return user_db
  return None
