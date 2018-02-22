"""k8s login command for OIDC / OAuth2

Uses the OAuth 2.0 "Native Apps" flow, documented at
https://tools.ietf.org/html/draft-ietf-oauth-native-apps-12
"""

# It would be more convenient to use an oauth2 or oidc library from pypi in
# this script, but they all seem to have a ton of dependencies, plus we need to
# do special trickery around SSL cert validation.

import base64
import BaseHTTPServer
import getpass
import json
import itertools
import os
import ssl
import sys
import subprocess
import time
import threading
import urllib
import urllib2
import urlparse
import uuid

from google.apputils import app
import botocore
import botocore.exceptions
import gflags
import glog as log

#### You will need to write your own of these two, sorry about that:
import clusterinfo
from scripts.lib.wrappers import kubectl

gflags.DEFINE_string(
    "client_id",
    "put-your-client-id-here",
    "OIDC client id")
gflags.DEFINE_string(
    "client_secret",
    "put-your-client-secret-here",
    "OIDC client secret")

gflags.DEFINE_string(
    "cluster", None,
    "Cluster name, e.g. 'stage' or 'stage.us-west-2.aws.k8s'")
gflags.MarkFlagAsRequired("cluster")
gflags.DEFINE_enum(
    "mode", "callback", ["callback", "oob"],
    "Auth flow variant. Use 'oob' if this script is not running on the"
    " same system as your web browser.")

FLAGS = gflags.FLAGS


class NoRedirectHandler(urllib2.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    https_response = http_response


class TokenServer(BaseHTTPServer.HTTPServer, object):

    def __init__(self, cluster):
        super(TokenServer, self).__init__(("localhost", 0), TokenHandler)

        self.cluster = clusterinfo.by_name(cluster)
        try:
            ca_cert = clusterinfo.get_cluster_ca_cert(self.cluster)
        except botocore.exceptions.BotoCoreError as err:
            raise K8sLoginError(
                "Failed to get the CA cert for this cluster: {}".format(err))

        ca_cert_fn = "{home}/.kube/{cluster.fullname}-ca.crt".format(
            home=os.getenv('HOME'),
            cluster=self.cluster)
        ca_dir = os.path.dirname(ca_cert_fn)
        if not os.path.exists(ca_dir):
            os.makedirs(ca_dir)
        with open(ca_cert_fn, 'w+') as ca_cert_file:
            ca_cert_file.write(ca_cert)
            ca_cert_file.seek(0)
            ca_cert_file.flush()

        ssl_context = ssl.create_default_context(capath=ca_cert_file.name)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        self.ca_cert_file = ca_cert_file

        http_client = urllib2.build_opener(
            urllib2.HTTPSHandler(context=ssl_context),
            NoRedirectHandler,
            urllib2.HTTPCookieProcessor())
        self.http_client = with_open_logger(http_client)

        self.nonce = uuid.uuid4()

        self.client_id = FLAGS.client_id
        self.client_secret = FLAGS.client_secret

        self.callback_uri = "http://localhost:%s/callback" % self.server_port

        log.info("Performing OIDC endpoint discovery...")
        try:
            self.discovery_info = json.load(
                http_client.open(
                    urlparse.urljoin(
                        self.cluster.oidc_endpoint,
                        ".well-known/openid-configuration")))
        except urllib2.URLError as err:
            raise K8sLoginError("Failed during OIDC discovery: {}".format(err))

    def get_auth_init_url(self):
        scopes = " ".join([
            "openid", "profile", "email", "groups", "offline_access",
            "audience:server:client_id:kubernetes",
        ])
        auth_init_response = self.http_client.open(
            "{url}?{args}".format(
                url=self.discovery_info.get("authorization_endpoint"),
                args=urllib.urlencode({
                    "client_id": self.client_id,
                    "redirect_uri": self.callback_uri,
                    "response_type": "code",
                    "scope": scopes,
                    "state": self.nonce,
                })))
        return auth_init_response.geturl()

    def redeem_code(self, code):
        """Redeem the auth code. Return Access, ID, and Refresh tokens.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        """
        request = urllib2.Request(
            self.discovery_info.get("token_endpoint"),
            data=urllib.urlencode({
                'grant_type': "authorization_code",
                'redirect_uri': self.callback_uri,
                'code': code,
            }),
            headers={
                "Authorization": "Basic {}".format(
                    base64.b64encode(
                        "{}:{}".format(self.client_id,
                                       self.client_secret).rstrip()
                    )
                )
            }
        )
        response = self.http_client.open(request)
        return json.load(response)

    def finish_auth(self, parsed_token, refresh_token):
        """Finish the process: call kubectl config, etc"""
        log.debug("Parsed id_token: %s", parsed_token)

        username = parsed_token.claims['email']

        kubectl_set_user(
            cluster=self.cluster,
            user=username,
            client_id=self.client_id,
            client_secret=self.client_secret,
            ca_cert_fn=self.ca_cert_file.name,
            id_token=parsed_token.raw_token,
            refresh_token=refresh_token,
            issuer=parsed_token.claims['iss'],
        )


class K8sLoginError(RuntimeError):
    """K8s login runtime error"""


class TokenHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Request handler for the browser callback oidc flow."""

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        log.debug(format, *args)

    def do_GET(self):  # pylint: disable=invalid-name
        """Handle http GET"""
        urlpath = urlparse.urlparse(self.path).path
        if urlpath == '/':
            redir_url = self.server.get_auth_init_url()
            self.send_response(302)
            self.send_header("Location", redir_url)
            self.end_headers()
            return
        elif urlpath != '/callback':
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<h1>404 That Is Not A Thing</h1>")
            return

        q_params = urlparse.parse_qs(urlparse.urlparse(self.path).query)

        try:
            response_state = "".join(q_params.get("state"))
        except TypeError:
            self.send_response(401)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<p>No state in response")
            return

        if str(response_state) != str(self.server.nonce):
            self.send_response(401)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<p>State in response did not match.")
            self.wfile.write("<p>Expected: %s" % self.server.nonce)
            self.wfile.write("<p>Got: %s" % response_state)
            return

        code = "".join(q_params.get("code", []))

        if not code:
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("No code in response.")
            return

        auth_data = self.server.redeem_code(code)

        if "id_token" not in auth_data:
            log.error("No id_token in auth_data: (%s)", auth_data)
            self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<p>No id_token in auth response")
            self.wfile.write("<p><pre>%s</pre>" % auth_data)
            return

        log.debug("Auth data: %s", auth_data)

        parsed_token = IdToken(auth_data["id_token"])
        self.server.finish_auth(parsed_token, auth_data["refresh_token"])

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        username = parsed_token.claims['email']
        for line in format_finish_msg(expires_in=auth_data['expires_in'],
                                      username=username):
            log.info(line)
            self.wfile.write("<p>%s" % line)
        self.wfile.write("<p>You can close this window now.")

        # Calling server.shutdown from inside the request handler will hang.
        # Let's have a thread do it for us instead.
        shutter = threading.Thread(target=self.server.shutdown)
        shutter.daemon = True
        shutter.start()


def format_finish_msg(expires_in, username):
    """Generate the 'all done' message"""
    expires_at = time.asctime(time.localtime(time.time() + expires_in))
    return [
        "Authenticated as {}.".format(username),
        ("Token expires in {:.1f} hours, at {}. "
         .format(expires_in / 60.0 / 60.0, expires_at)),
        "Using kubectl will refresh it.",
    ]


def kubectl_config(args):
    """Run kubectl config <args>"""
    kubectl.check_output(["config"] + list(args))


def kubectl_set_user(cluster, user, client_id, client_secret, ca_cert_fn,
                     id_token, refresh_token, issuer):
    """Run the various kubectl config steps"""
    auth_provider_args = map("=".join, [
        ("extra-scopes", "groups"),
        ("idp-issuer-url", issuer),
        ("id-token", id_token),
        ("client-id", client_id),
        ("client-secret", client_secret),
        ("refresh-token", refresh_token),
        ("idp-certificate-authority", ca_cert_fn)
    ])

    kube_user = "{}-{}".format(cluster.fullname, user)

    kubectl_config([
        "set-credentials", kube_user,
        "--auth-provider", "oidc"
    ] + zipcat(itertools.repeat("--auth-provider-arg"), auth_provider_args))
    try:
        # Delete and recreate the cluster entry to drop the
        # certificate-authority field that we're no longer setting:
        kubectl_config([
            "delete-cluster",
            cluster.fullname
        ])
    except subprocess.CalledProcessError:
        # This probably means the cluster config just didn't exist yet
        pass
    kubectl_config([
        "set-cluster", cluster.fullname,
        # Not needed since our external endpoints have "real" SSL certs
        # (in fact this doesn't work, because the external cert isn't issued by
        #  the in-cluster CA)
        # "--certificate-authority", ca_cert_fn,
        "--server", cluster.api_endpoint,
    ])
    kubectl_config([
        "set-context", cluster.fullname,
        "--cluster", cluster.fullname,
        "--user", kube_user
    ])
    kubectl_config([
        "use-context", cluster.fullname
    ])


def zipcat(seq1, seq2):
    """zip two sequences and concatenate the resulting tuples into a list.

    >>> zipcat([1, 2, 3, 4], ["a", "b", "c", "d"])
    [1, "a", 2, "b", 3, "c", 4, "d"]
    """
    return list(reduce(lambda a, b: a+b, zip(seq1, seq2)))


def open_url_in_browser(url):
    """Open a URL in the user's web browser, or prompt the user to do it."""
    if sys.platform == "darwin":
        cmd = ["open", url]
    elif sys.platform == "linux2":
        cmd = ["xdg-open", url]
    elif sys.platform in ["win32", "cygwin"]:
        cmd = ["start", url]
    try:
        subprocess.check_call(cmd)
    except (OSError, subprocess.CalledProcessError) as err:
        log.debug("Failed to launch a browser. (%s)", err)
        log.info("Please load this URL in your web browser to continue:"
                 "\n\n\t%s\n", url)
    else:
        log.info("Hopefully just opened this URL in your browser:\n\n\t%s\n",
                 url)
        log.info("Please check your browser to continue.")


def run_callback_flow(cluster):
    """Run the browser callback auth flow"""
    httpd = TokenServer(cluster)
    continue_url = "http://localhost:%s" % httpd.server_port
    open_url_in_browser(continue_url)
    log.info("Waiting for browser login...")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


def run_oob_flow(cluster):
    """Run the out-of-browser auth flow"""
    httpd = TokenServer(cluster)
    httpd.callback_uri = "urn:ietf:wg:oauth:2.0:oob"
    # note: magic oob uri above is from the dex Public Clients docs
    continue_url = httpd.get_auth_init_url()
    open_url_in_browser(continue_url)

    code = getpass.getpass("Paste the auth code from your browser here: ")
    auth_data = httpd.redeem_code(code)
    raw_id_token = auth_data.get("id_token")
    if not raw_id_token:
        log.error("No id_token in auth_data: (%s)", auth_data)
        return 1

    parsed_token = IdToken(raw_id_token)
    refresh_token = auth_data["refresh_token"]
    httpd.finish_auth(parsed_token, refresh_token)

    username = parsed_token.claims["email"]
    for line in format_finish_msg(auth_data['expires_in'], username):
        log.info(line)


def with_open_logger(obj):
    """Add a log.debug around obj.open()

    Args:
        obj: urllib2.OpenerDirector instance, probably.
    """
    orig_open = obj.open

    def new_open(fullurl, *args, **kwargs):
        # "fullurl" to match the parent function's args
        log_url = fullurl
        if isinstance(fullurl, urllib2.Request):
            log_url = fullurl.get_full_url()
        log.debug("http request: %s", log_url)
        return orig_open(fullurl, *args, **kwargs)
    obj.open = new_open
    return obj


class IdToken(object):
    """Parse an OpenID Connect ID Token.

    http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    http://openid.net/specs/openid-connect-core-1_0.html#id_tokenExample
    """
    def __init__(self, token):
        self.raw_token = token

        (jose_header, claims, signature) = token.split(".")
        self.jose_header = json.loads(self.b64decode(jose_header))
        self.claims = json.loads(self.b64decode(claims))
        self.raw_sig = signature

    @staticmethod
    def b64decode(data):
        """Fix padding if necessary, then base64 decode."""
        return base64.b64decode(data + '=' * (len(data) % 4))

    def __repr__(self):
        return "\n".join([
            "IdToken.header: %s" % json.dumps(self.jose_header, indent=2),
            "IdToken.claims: %s" % json.dumps(self.claims, indent=2),
            "IdToken.signature: %s" % self.raw_sig,
        ])


def main(argv):
    if len(argv) != 1:
        raise app.UsageError("Expected 0 positional args")

    try:
        if FLAGS.mode == "oob":
            run_oob_flow(cluster=FLAGS.cluster)
        elif FLAGS.mode == "callback":
            run_callback_flow(cluster=FLAGS.cluster)
        else:
            raise AssertionError("Internal error! Unknown mode: %s" %
                                 FLAGS.mode)
    except K8sLoginError as err:
        log.error(err)
        sys.exit(1)

if __name__ == '__main__':
    app.run()
