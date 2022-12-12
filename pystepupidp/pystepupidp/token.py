import logging
import requests

from flask import (
        Blueprint,
        current_app,
        render_template,
        redirect,
        session,
        url_for
        )

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

logger = logging.getLogger(__name__)


def validate_totp_input(form, field):

    # Testing the code is expensive so do not call out to the token manager
    # service if there are already errors attached to the form.
    if form.errors:
        logger.debug("Already have errors....")
        raise ValidationError('Existing form errors')

    name_id = session['name_id']
    logger.info("NameID from session is {}".format(name_id))

    privacyidea_config = current_app.config['IDP_CONFIG']['privacyidea']
    privacyidea_url = privacyidea_config['server_url']
    privacyidea_validate_token = privacyidea_config['validate_token']

    headers = {
        'Authorization': privacyidea_validate_token,
        'Accept': 'application/json'
    }

    realm = privacyidea_config['user_realm']

    # TODO Careful about cleansing the field.data here.
    path = '/validate/samlcheck?user={}&pass={}&realm={}'
    path = path.format(name_id, field.data, realm)
    url = privacyidea_url + path

    resp = requests.get(url, headers=headers)

    validation_response = resp.json()

    logger.debug(validation_response)

    # TODO Need to do more checking here about API detail and so on.
    if not validation_response['result']['value']['auth']:
        raise ValidationError('Wrong code')

    logger.info("token successfully validated")


class TotpInputForm(FlaskForm):
    code = StringField('One-time security code',
                       validators=[DataRequired(),
                                   Length(min=6, max=6),
                                   validate_totp_input
                                   ]
                       )
    submit = SubmitField('Submit')


class TanInputForm(FlaskForm):
    tancode = StringField('One-time backup code',
                       validators=[DataRequired(),
                                   Length(min=6, max=30),
                                   validate_totp_input
                                   ]
                       )
    tansubmit = SubmitField('Submit')

bp = Blueprint('token', __name__, url_prefix='/token')


@bp.route('/', methods=('GET',))
def token_index():

    # Error if cannot find user in session...

    name_id = session['name_id']
    logger.info("NameID from session is {}".format(name_id))

    # Should determine if more than one token here and display
    # a way for user to choose which token to use. For now we
    # assume one TOTP token.

    return redirect(url_for('token.token_totp'))


@bp.route('/totp', methods=('GET', 'POST'))
def token_totp():
    form = TotpInputForm()
    name_id = session['name_id']

    if form.validate_on_submit():
        session['mfa_auth'] = True
        return redirect(url_for('saml.send_assertion'))

    return render_template('token_totp.html', form=form, name_id=name_id)

@bp.route('/tan', methods=('GET', 'POST'))
def token_tan():
    form = TanInputForm()
    name_id = session['name_id']

    if form.validate_on_submit():
        session['mfa_auth'] = True
        return redirect(url_for('saml.send_assertion'))

    return render_template('token_tan.html', form=form, name_id=name_id)


