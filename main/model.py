# -*- coding: utf-8 -*-

from google.appengine.ext import ndb
import util
import os
import modelx


# The timestamp of the currently deployed version
TIMESTAMP = long(os.environ.get('CURRENT_VERSION_ID').split('.')[1]) >> 28


class Base(ndb.Model, modelx.BaseX):
  created = ndb.DateTimeProperty(auto_now_add=True)
  modified = ndb.DateTimeProperty(auto_now=True)
  version = ndb.IntegerProperty(default=TIMESTAMP)
  _PROPERTIES = {
      'key',
      'id',
      'version',
      'created',
      'modified',
    }


class Config(Base, modelx.ConfigX):
  analytics_id = ndb.StringProperty(default='')
  announcement_html = ndb.StringProperty(default='')
  announcement_type = ndb.StringProperty(default='info', choices=[
      'info', 'warning', 'success', 'danger',
    ])
  bitbucket_key = ndb.StringProperty(default='')
  bitbucket_secret = ndb.StringProperty(default='')
  brand_name = ndb.StringProperty(default='gae-init')
  dropbox_app_key = ndb.StringProperty(default='')
  dropbox_app_secret = ndb.StringProperty(default='')
  facebook_app_id = ndb.StringProperty(default='')
  facebook_app_secret = ndb.StringProperty(default='')
  feedback_email = ndb.StringProperty(default='')
  flask_secret_key = ndb.StringProperty(default=util.uuid())
  github_client_id = ndb.StringProperty(default='')
  github_client_secret = ndb.StringProperty(default='')
  linkedin_api_key = ndb.StringProperty(default='')
  linkedin_secret_key = ndb.StringProperty(default='')
  twitter_consumer_key = ndb.StringProperty(default='')
  twitter_consumer_secret = ndb.StringProperty(default='')
  vk_app_id = ndb.StringProperty(default='')
  vk_app_secret = ndb.StringProperty(default='')
  windowslive_client_id = ndb.StringProperty(default='')
  windowslive_client_secret = ndb.StringProperty(default='')

  _PROPERTIES = Base._PROPERTIES.union({
      'analytics_id',
      'announcement_html',
      'announcement_type',
      'bitbucket_key',
      'bitbucket_secret',
      'brand_name',
      'dropbox_app_key',
      'dropbox_app_secret',
      'facebook_app_id',
      'facebook_app_secret',
      'feedback_email',
      'flask_secret_key',
      'github_client_id',
      'github_client_secret',
      'linkedin_api_key',
      'linkedin_secret_key',
      'twitter_consumer_key',
      'twitter_consumer_secret',
      'vk_app_id',
      'vk_app_secret',
      'windowslive_client_id',
      'windowslive_client_secret',
    })


class User(Base, modelx.UserX):
  name = ndb.StringProperty(indexed=True, required=True)
  username = ndb.StringProperty(indexed=True, required=True)
  email = ndb.StringProperty(indexed=True, default='')
  auth_ids = ndb.StringProperty(indexed=True, repeated=True)

  active = ndb.BooleanProperty(default=True)
  admin = ndb.BooleanProperty(default=False)

  _PROPERTIES = Base._PROPERTIES.union({
      'active',
      'admin',
      'auth_ids',
      'avatar_url',
      'email',
      'name',
      'username',
    })
