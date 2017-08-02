from werkzeug.wrappers import Request, Response
from pprint import pprint
import json
import plivo
import base64
import hmac
import hashlib

def validate_signature(uri, post_params, signature, auth_token):
    """
    Validates requests made by Plivo to your servers.
    See https://www.plivo.com/docs/xml/request/#validation

    :param uri: Your server URL
    :param post_params: POST Parameters passed to your URL, in case of POST request. Will be ignored if URL contains a
    query string
    :param auth_token: Plivo Auth token
    :param signature: X-Plivo-Signature header
    :return: True if the request matches signature, False otherwise
    """
    all_params = post_params or {}
    encoded_request = uri.encode('utf-8')
    for k, v in sorted(all_params.items()):
        encoded_key = k.encode('utf-8')
        encoded_val = v.encode('utf-8')
        encoded_request += encoded_key + encoded_val
    gen_sig = base64.encodestring(hmac.new(auth_token.encode('utf-8'), encoded_request, hashlib.sha1).digest()).strip()
    #To-Do - This implementation is not complete yet
    print('Generated Sign {}, Header Sign:{}'.format(gen_sig, signature))

    return gen_sig == signature


@Request.application
def application(request):
    pprint(request.__dict__)
    url = request.url
    print('------------------------------------------{}'.format(url))
    content_type = request.headers.get('content-type')
    print('Content Type: {}'.format(content_type))
    if content_type == 'application/json':
        pprint(request.data)
    elif content_type == 'application/x-www-form-urlencoded':
        pprint(request.form)
        signature = request.headers.get('X-Plivo-Signature')
        if signature: # Do some plivo processing
            auth_token = 'ODRmYWRlMjAwOGY1OTAzMGNhOWM1MDNjNDM5MTM4'
            params = dict((key, request.form.getlist(key)[0]) for key in request.form.keys())
            print('Signature is {}'.format(validate_signature(url, params, signature, auth_token)))
    elif content_type == 'multipart/form-data':
        pprint(request.form)
    else:
        pprint(request.data)
    print('------------------------------------------')
    return Response('Ok')

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    run_simple('localhost', 4000, application)
    run_simple('localhost', 4000, application)
