# NoraTSC

NoraTSC (Nora Tor Socket Controller) Is a Web browser made with python using primaraly the python library [PySide6](https://pypi.org/project/PySide6/) is focused on __security__. It uses [Tor](https://www.torproject.org/) to establish a secure link to the web server. It uses the [Stem library](https://pypi.org/project/stem/) to control Tor connections and funcions. Some of PySide6's built-in functions are used for features such as redirect blocking, popup blocking, and Ad blocking. Their is anti-fingerprinting measures being taken, but it is still many years behind other browsers like [Tor](https://www.torproject.org/). The current version (1.134), currently refurd to as SecBrowser, is still in the beta stage. Their are still errors that need to be resolved, but I will leave a download link for this older version. We would accept donations, but this project is still so new (created 5/19/2026) that we have not set up any services like [Buy Me A Coffee](https://buymeacoffee.com/). Thank you! Please post issues in the "issues section".

Code


```python
import os
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join([
    "--disable-features=UseDnsHttpsSvcb",

    "--proxy-server=socks5h://127.0.0.1:9050",

    "--disable-dns-over-https",

    "--disable-webrtc",

    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",

    "--disable-sync",

    "--disable-plugins",

    "--disable-extensions",

    "--disable-background-networking",

    "--disable-features=AutofillServerCommunication"

])
import sys
from stem.process import launch_tor_with_config
from stem.control import Controller
from PySide6.QtWidgets import *
from PySide6.QtWebEngineWidgets import *
from PySide6.QtCore import QUrl
from PySide6.QtNetwork import QNetworkProxy
from PySide6.QtWebEngineCore import *
from PySide6.QtCore import Qt

try:
    tor_process = launch_tor_with_config(
        tor_cmd = r".\tor\tor.exe",
        config = {
            'SocksPort': '9050',
            'ControlPort': '9051',
        },
        completion_percent = 100,
    )
except OSError as e:
    if "Failed to bind" in str(e):
        print("Tor is already running, connecting to existing instance...")
        tor_process = None
    else:
        raise
with Controller.from_port(port=9051) as controller:

    controller.authenticate()

    print(
        controller.get_info("version")
    )

# CHROMIUM FLAGS

app = QApplication(sys.argv)

# TOR SOCKS5 PROXY
torproxy = QNetworkProxy()

torproxy.setType(
    QNetworkProxy.ProxyType.Socks5Proxy
)

torproxy.setHostName("127.0.0.1")

torproxy.setPort(9050)

QNetworkProxy.setApplicationProxy(torproxy)

# MAIN WINDOW
window = QMainWindow()

window.resize(1200, 800)

window.setWindowTitle(
    "SecBrowser beta 1.134"
)

# LAYOUT
layout = QVBoxLayout()

# WEBENGINE
browser_win = QWebEngineView()
settings = browser_win.settings()
settings.setAttribute(
    QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows,
    False
)
class TrackerAdRedirectBlocker(
    QWebEngineUrlRequestInterceptor
):

    def interceptRequest(self, info):

        url = info.requestUrl().toString()
        domain = info.requestUrl().host().lower()
        trackers = [
            "google-analytics.com",
            "googletagmanager.com",
            "doubleclick.net",
            "facebook.net",
            "connect.facebook.net",
            "mixpanel.com",
            "hotjar.com",
            "segment.io",
            "scorecardresearch.com"
        ]

        for tracker in trackers:

            if (
                domain == tracker or
                domain.endswith("." + tracker)
            ):

                print("Blocked tracker:", url)

                info.block(True)

                return

        
        blocked = [            
            "googleads",
            "googlesyndication",
            "adsystem",
            "adservice",
            "doubleclick.net"
        ]
        for item in blocked:

            if item in url:

                info.block(True)
                print(f"Blocked: {url}")

                return

        

        
        # Block requests that look like redirect attempts
        suspicious_keywords = [
            "redirect",
            "popup",
            "exit",
            "promo",
            "offer"
        ]
        
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                # Extra check: if it has target="_parent" in referrer or similar
                info.block(True)
                print(f"Blocked suspicious content: {url}")
                return







settings.setAttribute(
    QWebEngineSettings.WebAttribute.FullScreenSupportEnabled,
    True
)

class SecurePage(QWebEnginePage):

    def acceptNavigationRequest(self, url, nav_type, isMainFrame):
        url_str = url.toString()
        domain = QUrl(url_str).host().lower()
        # Block tracker and ad domains
        blocked = [
            "tracker",
            "adservice",
            "google-analytics.com",
            "googletagmanager.com",
            "doubleclick.net",
            "facebook.net",
            "connect.facebook.net",
            "analytics",
            "tracking",
            "telemetry",
            "mixpanel",
            "hotjar",
            "segment.io",
            "adsystem",
            "scorecardresearch",
            "googleads",
            "googlesyndication",
            "googleadservices.com",
            "bit.ly",
            "t.co"
        ]
        
        for item in blocked:
            if domain == item or domain.endswith("." + item):
                print("Blocked navigation:", domain)
                return False
        
        # Redirect HTTP to HTTPS
        if url_str.startswith("http://"):

            secure = QUrl(url_str.replace("http://", "https://", 1))

            self.setUrl(secure)

            return False
        
        # Block cross-domain iframes (potential redirects)
# Smarter iframe filtering
        if not isMainFrame:

            iframe_domain = QUrl(url_str).host().lower()

            blocked_iframe_domains = [
                "doubleclick.net",
                "googlesyndication.com",
                "googleadservices.com",
                "adsystem.com",
                "tracker.com",
                "popads.net",
                "adnxs.com"
            ]

            for blocked in blocked_iframe_domains:

                if (
                    iframe_domain == blocked or
                    iframe_domain.endswith("." + blocked)
                ):

                    print(f"Blocked iframe: {iframe_domain}")

                    return False
        
        return super().acceptNavigationRequest(url, nav_type, isMainFrame)

    def createWindow(self, window_type):

        popup = QWebEngineView()

        popup.setAttribute(Qt.WA_DeleteOnClose)

        popup_page = SecurePage(profile)

        popup.setPage(popup_page)

        popup.resize(800, 600)

        popup.show()

        return popup_page

# Create off-the-record profile BEFORE setting the page
profile = QWebEngineProfile()

secure_page = SecurePage(profile)

browser_win.setPage(secure_page)

# Inject script to block window.open() BEFORE page scripts run
script = QWebEngineScript()
script.setSourceCode("""
(function() {
    window.open = function() {
        console.log('window.open() blocked');
        return null;
    };
    
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('iframe').forEach(iframe => {
            iframe.removeAttribute('target');
        });
        document.querySelectorAll('base').forEach(base => {
            base.removeAttribute('target');
        });
    }, false);
    
    if (document.documentElement) {
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(mutation => {
                if (mutation.addedNodes.length) {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1) {
                            if (node.tagName === 'IFRAME' || node.tagName === 'BASE') {
                                node.removeAttribute('target');
                            }
                            if (node.querySelectorAll) {
                                node.querySelectorAll('iframe, base').forEach(el => {
                                    el.removeAttribute('target');
                                });
                            }
                        }
                    });
                }
            });
        });
        
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    }
})();
""")
script.setInjectionPoint(QWebEngineScript.DocumentCreation)
script.setRunsOnSubFrames(True)
profile.scripts().insert(script)

profile.setHttpUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/122.0 Safari/537.36"
)

profile.cookieStore().deleteAllCookies()

profile.setPersistentCookiesPolicy(
    QWebEngineProfile.NoPersistentCookies
)


profile.setUrlRequestInterceptor(TrackerAdRedirectBlocker())

profile.setPersistentStoragePath("")
profile.setCachePath("")

profile.setHttpAcceptLanguage(
    "en-US,en;q=0.9"
)

def loaded(ok):

    if ok:
        # Block window.open() calls
        browser_win.page().runJavaScript("""
        window.open = function() {
            console.log('window.open() blocked');
            return null;
        };
        """)

        # Block iframes with target="_parent" or target="_top"
        browser_win.page().runJavaScript("""
        document.querySelectorAll('iframe').forEach(iframe => {
            if (iframe.getAttribute('target') === '_parent' || 
                iframe.getAttribute('target') === '_top') {
                console.log('Blocked iframe redirect:', iframe.src);
                iframe.remove();
            }
        });
        """)

        # Block base tags that redirect
        browser_win.page().runJavaScript("""
        document.querySelectorAll('base').forEach(base => {
            if (base.getAttribute('target') === '_parent' || 
                base.getAttribute('target') === '_top') {
                console.log('Blocked base tag redirect:', base.href);
                base.remove();
            }
        });
        """)

        # Remove ads
        browser_win.page().runJavaScript("""

        document.querySelectorAll('.ads')
        .forEach(el => el.remove());

        """)
        
        # Spoof navigator.platform

        
        # Spoof screen.width


# FULLSCREEN SUPPORT
def handle_fullscreen(request):

    request.accept()

    if request.toggleOn():

        window.showFullScreen()

    else:

        window.showNormal()

browser_win.page().fullScreenRequested.connect(
    handle_fullscreen
)

# Connect page load signal
browser_win.page().loadFinished.connect(loaded)

# LOAD WEBSITE
browser_win.load(
    QUrl("https://noai.duckduckgo.com/")
)

# ADD TO LAYOUT
layout.addWidget(browser_win)

container = QWidget()

container.setLayout(layout)

window.setCentralWidget(container)

window.show()

sys.exit(app.exec())
```


You can download this from the versions page.

