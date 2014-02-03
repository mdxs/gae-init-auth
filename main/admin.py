# -*- coding: utf-8 -*-

from flask.ext import wtf
from google.appengine.api import app_identity
import flask

import auth
import util
import model
import config

from main import app


class ConfigUpdateForm(wtf.Form):
  analytics_id = wtf.StringField('Analytics ID', filters=[util.strip_filter])
  announcement_html = wtf.TextAreaField('Announcement HTML', filters=[util.strip_filter])
  announcement_type = wtf.SelectField('Announcement Type', choices=[(t, t.title()) for t in model.Config.announcement_type._choices])
  bitbucket_key = wtf.StringField('Bitbucket Key', filters=[util.strip_filter])
  bitbucket_secret = wtf.StringField('Bitbucket Secret', filters=[util.strip_filter])
  brand_name = wtf.StringField('Brand Name', [wtf.validators.required()], filters=[util.strip_filter])
  dropbox_app_key = wtf.StringField('Dropbox App Key', filters=[util.strip_filter])
  dropbox_app_secret = wtf.StringField('Dropbox App Secret', filters=[util.strip_filter])
  facebook_app_id = wtf.StringField('Facebook App ID', filters=[util.strip_filter])
  facebook_app_secret = wtf.StringField('Facebook App Secret', filters=[util.strip_filter])
  feedback_email = wtf.StringField('Feedback Email', [wtf.validators.optional(), wtf.validators.email()], filters=[util.email_filter])
  flask_secret_key = wtf.StringField('Flask Secret Key', [wtf.validators.required()], filters=[util.strip_filter])
  github_client_id = wtf.StringField('GitHub Client ID', filters=[util.strip_filter])
  github_client_secret = wtf.StringField('GitHub Client Secret', filters=[util.strip_filter])
  instagram_client_id = wtf.StringField('Instagram Client ID', filters=[util.strip_filter])
  instagram_client_secret = wtf.StringField('Instagram Client Secret', filters=[util.strip_filter])
  linkedin_api_key = wtf.StringField('LinkedIn API Key', filters=[util.strip_filter])
  linkedin_secret_key = wtf.StringField('LinkedIn Secret Key', filters=[util.strip_filter])
  reddit_client_id = wtf.StringField('Reddit Key', filters=[util.strip_filter])
  reddit_client_secret = wtf.StringField('Reddit Secret', filters=[util.strip_filter])
  stackoverflow_client_id = wtf.StringField('Stack Overflow Client Id', filters=[util.strip_filter])
  stackoverflow_client_secret = wtf.StringField('Stack Overflow Client Secret', filters=[util.strip_filter])
  stackoverflow_key = wtf.StringField('Stack Overflow Key', filters=[util.strip_filter])
  twitter_consumer_key = wtf.StringField('Twitter Consumer Key', filters=[util.strip_filter])
  twitter_consumer_secret = wtf.StringField('Twitter Consumer Secret', filters=[util.strip_filter])
  vk_app_id = wtf.StringField('VK App ID', filters=[util.strip_filter])
  vk_app_secret = wtf.StringField('VK App Secret', filters=[util.strip_filter])
  windowslive_client_id = wtf.StringField('Windows Live Client ID', filters=[util.strip_filter])
  windowslive_client_secret = wtf.StringField('Windows Live Client secret', filters=[util.strip_filter])
  yahoo_consumer_key = wtf.StringField('Yahoo! Consumer Key', filters=[util.strip_filter])
  yahoo_consumer_secret = wtf.StringField('Yahoo! Consumer Secret', filters=[util.strip_filter])


@app.route('/_s/admin/config/', endpoint='admin_config_update_service')
@app.route('/admin/config/', methods=['GET', 'POST'])
@auth.admin_required
def admin_config_update():
  config_db = model.Config.get_master_db()
  form = ConfigUpdateForm(obj=config_db)
  if form.validate_on_submit():
    form.populate_obj(config_db)
    config_db.put()
    reload(config)
    app.config.update(CONFIG_DB=config_db)
    return flask.redirect(flask.url_for('welcome'))

  if flask.request.path.startswith('/_s/'):
    return util.jsonify_model_db(config_db)

  instances_url = None
  if config.PRODUCTION:
    instances_url = '%s?app_id=%s&version_id=%s' % (
        'https://appengine.google.com/instances',
        app_identity.get_application_id(),
        config.CURRENT_VERSION_ID,
      )

  return flask.render_template(
      'admin/config_update.html',
      title='Admin Config',
      html_class='admin-config',
      form=form,
      config_db=config_db,
      instances_url=instances_url,
      has_json=True,
    )
