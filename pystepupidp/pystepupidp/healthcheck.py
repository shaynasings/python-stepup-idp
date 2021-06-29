import logging

from flask import (
        Blueprint,
        current_app
        )

logger = logging.getLogger(__name__)

bp = Blueprint('healthcheck', __name__, url_prefix='/healthcheck')

@bp.route('/ping', methods=('GET',))
def ping():
    return ('', 204)
