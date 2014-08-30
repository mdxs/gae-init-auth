# coding: utf-8

from flask.ext import wtf
from google.appengine.api import app_identity
import flask
import wtforms

import auth
import config
import model
import util

from main import app


class ConfigUpdateForm(wtf.Form):
  analytics_id = wtforms.StringField('Tracking ID', filters=[util.strip_filter])
  announcement_html = wtforms.TextAreaField('Announcement HTML', filters=[util.strip_filter])
  announcement_type = wtforms.SelectField('Announcement Type', choices=[(t, t.title()) for t in model.Config.announcement_type._choices])
  bitbucket_key = wtforms.StringField('Key', filters=[util.strip_filter])
  bitbucket_secret = wtforms.StringField('Secret', filters=[util.strip_filter])
  brand_name = wtforms.StringField('Brand Name', [wtforms.validators.required()], filters=[util.strip_filter])
  check_unique_email = wtforms.BooleanField('Check for the uniqueness of the verified emails')
  dropbox_app_key = wtforms.StringField('App Key', filters=[util.strip_filter])
  dropbox_app_secret = wtforms.StringField('App Secret', filters=[util.strip_filter])
  facebook_app_id = wtforms.StringField('App ID', filters=[util.strip_filter])
  facebook_app_secret = wtforms.StringField('App Secret', filters=[util.strip_filter])
  feedback_email = wtforms.StringField('Feedback Email', [wtforms.validators.optional(), wtforms.validators.email()], filters=[util.email_filter])
  flask_secret_key = wtforms.StringField('Secret Key', [wtforms.validators.optional()], filters=[util.strip_filter])
  github_client_id = wtforms.StringField('Client ID', filters=[util.strip_filter])
  github_client_secret = wtforms.StringField('Client Secret', filters=[util.strip_filter])
  instagram_client_id = wtforms.StringField('Client ID', filters=[util.strip_filter])
  instagram_client_secret = wtforms.StringField('Client Secret', filters=[util.strip_filter])
  linkedin_api_key = wtforms.StringField('API Key', filters=[util.strip_filter])
  linkedin_secret_key = wtforms.StringField('Secret Key', filters=[util.strip_filter])
  microsoft_client_id = wtforms.StringField('Client ID', filters=[util.strip_filter])
  microsoft_client_secret = wtforms.StringField('Client Secret', filters=[util.strip_filter])
  notify_on_new_user = wtforms.BooleanField('Send an email notification when a user signs up')
  reddit_client_id = wtforms.StringField('Key', filters=[util.strip_filter])
  reddit_client_secret = wtforms.StringField('Secret', filters=[util.strip_filter])
  stackoverflow_client_id = wtforms.StringField('Client Id', filters=[util.strip_filter])
  stackoverflow_client_secret = wtforms.StringField('Client Secret', filters=[util.strip_filter])
  stackoverflow_key = wtforms.StringField('Key', filters=[util.strip_filter])
  twitter_consumer_key = wtforms.StringField('Consumer Key', filters=[util.strip_filter])
  twitter_consumer_secret = wtforms.StringField('Consumer Secret', filters=[util.strip_filter])
  verify_email = wtforms.BooleanField('Verify user emails')
  vk_app_id = wtforms.StringField('App ID', filters=[util.strip_filter])
  vk_app_secret = wtforms.StringField('App Secret', filters=[util.strip_filter])
  yahoo_consumer_key = wtforms.StringField('Consumer Key', filters=[util.strip_filter])
  yahoo_consumer_secret = wtforms.StringField('Consumer Secret', filters=[util.strip_filter])


@app.route('/_s/admin/config/', endpoint='admin_config_update_service')
@app.route('/admin/config/', methods=['GET', 'POST'])
@auth.admin_required
def admin_config_update():
  config_db = model.Config.get_master_db()
  form = ConfigUpdateForm(obj=config_db)
  if form.validate_on_submit():
    form.populate_obj(config_db)
    if not config_db.flask_secret_key:
      config_db.flask_secret_key = util.uuid()
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
