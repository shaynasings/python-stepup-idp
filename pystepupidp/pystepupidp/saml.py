import copy
import ldap3
import logging
import requests

from base64 import b64encode

from flask import (
        Blueprint,
        abort,
        current_app,
        redirect,
        render_template,
        request,
        session,
        url_for
        )

# from markupsafe import escape

from saml2 import BINDING_HTTP_REDIRECT
from saml2.config import IdPConfig
from saml2.request import Request
from saml2.samlp import NameIDPolicy
from saml2.server import Server

from xml.dom import minidom

logger = logging.getLogger(__name__)

bp = Blueprint('saml', __name__, url_prefix='/saml/sso')


@bp.route('/redirect', methods=('GET',))
def consume_auth_request():

    # Kill any existing session
    session.clear()

    saml_request = request.args.get('SAMLRequest', None)
    relay_state = request.args.get('RelayState', None)
    signature = request.args.get('Signature', None)
    signature_alg = request.args.get('SigAlg', None)

    if not all([saml_request, relay_state, signature, signature_alg]):
        msg = ("Received malformed HTTP-Redirect request, missing at least "
               "one of these query parameters: SAMLRequest, RelayState, "
               "Signature, SigAlg.")
        logger.error(msg)
        abort(400)

    logger.debug("SAMLRequest is {}".format(saml_request))
    logger.debug("RelayState is {}".format(relay_state))
    logger.debug("Signature is {}".format(signature))
    logger.debug("SigAlg is {}".format(signature_alg))

    idp_config = current_app.config['IDP_CONFIG']
    idp_config_object = IdPConfig().load(copy.deepcopy(idp_config),
                                         metadata_construction=False)
    idp = Server(config=idp_config_object)

    # TODO
    # Need to check signature here or does the parse below do that?
    # What about replay?
    # What about time skew?

    try:
        parsed_request = idp.parse_authn_request(saml_request,
                                                 BINDING_HTTP_REDIRECT)
    except Exception as e:
        msg = "Caught exception while parsing SAMLRequest: {}".format(e)
        logger.error(msg)
        abort(400)

    if not isinstance(parsed_request, Request):
        msg = "Received invalid SAMLRequest"
        logger.error(msg)
        abort(400)

    authn_request = parsed_request.message
    msg = "Parsed SAML request is \n{}"
    msg = msg.format(minidom.parseString(
            str(authn_request)).toprettyxml(indent=' '))
    logger.debug(msg)

    subject = authn_request.subject
    name_id = subject.name_id.text if subject else None

    if not name_id:
        msg = "Unable to obtain NameID from SAMLRequest"
        logger.error(msg)
        abort(400)

    logger.info("NameID is {}".format(name_id))

    # Use the name ID to query LDAP

    ldap_config = current_app.config['IDP_CONFIG']['ldap']
    url = ldap_config['server_url']
    bind_dn = ldap_config['bind_dn']
    bind_password = ldap_config['bind_password']
    search_base = ldap_config['search_base']
    search_filter_template = ldap_config['search_filter_template']

    ldap_server = ldap3.Server(url)

    args = {
        'server': ldap_server,
        'user': bind_dn,
        'password': bind_password,
        'auto_bind': True
        }
    ldap_connection = ldap3.Connection(**args)

    args = {
        'search_base': search_base,
        'search_filter': search_filter_template.format(name_id),
        'search_scope': ldap3.SUBTREE,
        'attributes': ldap3.ALL_ATTRIBUTES
        }

    ldap_connection.search(**args)

    ldap_response = ldap_connection.response

    # TODO Should send back a SAML error.
    if len(ldap_response) == 0:
        msg = "LDAP query with search filter {} returned zero results"
        msg = msg.format(args['search_filter'])
        logger.error(msg)
        abort(400)

    # TODO Should send back a SAML error.
    if len(ldap_response) > 1:
        msg = "LDAP query with search filter {} returned multiple results"
        msg = msg.format(args['search_filter'])
        logger.error(msg)
        abort(400)

    logger.debug(ldap_response[0])

    privacyidea_config = current_app.config['IDP_CONFIG']['privacyidea']
    privacyidea_url = privacyidea_config['server_url']
    privacyidea_admin_token = privacyidea_config['admin_token']

    headers = {
        'Authorization': privacyidea_admin_token,
        'Accept': 'application/json'
    }

    url = privacyidea_url + '/token/?user={}'.format(name_id)

    # TODO Catch exceptions
    resp = requests.get(url, headers=headers)
    token_response = resp.json()

    logger.debug(token_response)

    if token_response['jsonrpc'] != '2.0':
        msg = "Invalid JSON RPC version number"
        logger.error(msg)
        abort(400)

    # User cannot be found
    # TODO Should send back a SAML error.
    result = token_response['result']
    if 'error' in result and result['error']['code'] == 904:
        err_msg = result['error']['message']
        msg = "Token query for user {} generated error: {}"
        msg = msg.format(name_id, err_msg)
        logger.error(msg)
        abort(400)

    # TODO Should send back a SAML error.
    if not token_response['result']['status']:
        msg = "Token query for user {} response status not True"
        msg = msg.format(name_id)
        logger.error(msg)
        abort(400)

    # TODO Need to do better here, handling case where the user is found but
    # for example has no tokens enabled.

    actionable_mfa_tokens = []

    for token in result['value']['tokens']:
        if token['tokentype'] == 'totp':
            actionable_mfa_tokens.append(token)

    if not actionable_mfa_tokens:
        # TODO Should send back SAML error.
        msg = "Could not find actionable MFA token for user {}".format(name_id)
        logger.error(msg)
        abort(400)

    # User is in LDAP and we have found at least one token we can work with
    # so start a session.
    session['name_id'] = name_id
    session['saml_authn_request_id'] = authn_request.id
    session['saml_sp_entity_id'] = authn_request.issuer.text
    session['saml_sp_acs'] = authn_request.assertion_consumer_service_url
    session['saml_relay_state'] = relay_state

    return redirect(url_for('token.token_index'))


@bp.route('/continue', methods=('GET',))
def send_assertion():
    logger.debug("Sending SAML assertion")

    idp_config = current_app.config['IDP_CONFIG']
    idp_config_object = IdPConfig().load(copy.deepcopy(idp_config),
                                         metadata_construction=False)
    idp = Server(config=idp_config_object)

    name_id_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    name_id_policy = NameIDPolicy(format=name_id_format)

    args = {
        'identity': {},
        'name_id': None,
        'authn': {
                'class_ref': 'https://refeds.org/profile/mfa',
                'authn_auth': idp_config['entityid']
            },
        'sign_response': True,
        'sign_assertion': False,
        'encrypted_advice_attributes': False,
        'in_response_to': session['saml_authn_request_id'],
        'sp_entity_id': session['saml_sp_entity_id'],
        'name_id_policy': name_id_policy,
        'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'destination': session['saml_sp_acs'],
        'sign_alg': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'digest_alg': 'http://www.w3.org/2001/04/xmlenc#sha256',
    }

    saml_response_string = idp.create_authn_response(**args)
    saml_response_string_encoded = saml_response_string.encode('utf-8')
    saml_response = b64encode(saml_response_string_encoded)
    saml_response_encoded = saml_response.decode('ascii')

    action = session['saml_sp_acs']
    saml_relay_state = session['saml_relay_state']
    rendered_template = render_template(
                            'saml_http_post_binding.html',
                            action=action,
                            saml_response_encoded=saml_response_encoded,
                            saml_relay_state=saml_relay_state
                            )

    # Kill the session
    session.clear()

    return rendered_template
