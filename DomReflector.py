from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
from java.lang import String

class BurpExtender(IBurpExtender, IHttpListener):

    DOM_SINKS = [
        "document.write", "document.writeln", "document.location",
        "location.href", "location.replace", "eval", "setTimeout",
        "setInterval", "innerHTML", "outerHTML", "window.name",
        "localStorage", "sessionStorage", "document.URL", "document.referrer"
    ]

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DOM XSS Detector - Phase 1")

        # Setup console output
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.stdout.println("== DOM XSS Detector Extension Loaded (Phase 1) ==")

        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process HTTP responses
        if messageIsRequest:
            return

        try:
            response_bytes = messageInfo.getResponse()
            analyzed_response = self.helpers.analyzeResponse(response_bytes)
            body_offset = analyzed_response.getBodyOffset()

            # Convert raw body to string using ISO-8859-1 to preserve byte content
            body = String(response_bytes[body_offset:], "ISO-8859-1").toString()

            # Check for known DOM XSS sinks
            found_sinks = [sink for sink in self.DOM_SINKS if sink in body]

            if found_sinks:
                url = self.helpers.analyzeRequest(messageInfo).getUrl()
                self.stdout.println("\n[!] Possible DOM XSS Detected!")
                self.stdout.println("URL: " + str(url))
                self.stdout.println("Sinks Found: " + ", ".join(found_sinks))
        except Exception as e:
            self.stderr.println("Error processing response: " + str(e))
