from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IHttpRequestResponse, IHttpService, IParameter
from javax.swing import JFrame, JPanel, JTable, JScrollPane, JTextArea, table, BoxLayout, JTabbedPane, JSplitPane, JLabel, JButton, SwingUtilities
from java.awt import BorderLayout, Color, Dimension, FlowLayout, Font
from java.awt.event import MouseAdapter, KeyEvent, KeyAdapter, ActionListener
from java.lang import Runnable
from java.net import URL


class MyMouseListener(MouseAdapter):
    def __init__(self, table, extender):
        self.table = table
        self.extender = extender

    def mouseClicked(self, e):
        row = self.table.getSelectedRow()
        if row != -1:
            # Perform the desired action when the user clicks on a row
            self.extender._requestViewer.setMessage(self.extender.data_requests[row], True)
            self.extender._responseViewer.setMessage(self.extender.data_responses[row], False)

class MyKeyListener(KeyAdapter):
    def __init__(self, table, extender):
        self.table = table
        self.extender = extender

    def keyPressed(self, e):
        if e.getKeyCode() == KeyEvent.VK_UP or e.getKeyCode() == KeyEvent.VK_DOWN:
            # Use invokeLater to ensure row is selected before getting it
            SwingUtilities.invokeLater(UpdateViewerRunnable(self.table, self.extender))

class UpdateViewerRunnable(Runnable):
    def __init__(self, table, extender):
        self.table = table
        self.extender = extender
    
    def run(self):
        row = self.table.getSelectedRow()
        if row != -1:
            self.extender._requestViewer.setMessage(self.extender.data_requests[row], True)
            self.extender._responseViewer.setMessage(self.extender.data_responses[row], False)

class ClearButtonListener(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, e):
        self.extender.clearResults()

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IHttpService, IHttpRequestResponse):
    
    def __init__(self):
        self.data = []
        self.data_requests = []
        self.data_responses = []
        self.panel = None
        self.tableModel = None
        self.id = 0
        self.modified_cookie_header = []
        self.splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.myTable = JTable()
        self._requestViewer = None
        self._responseViewer = None
        self.editor_panel = JPanel(BorderLayout())
        self.stats_label = None
        self.tested_urls = set()  # Track tested URLs to avoid duplicates

    def getTabCaption(self):
        return "isXSS"

    def getUiComponent(self):
        if not self.panel:  # Only create panel once
            self.panel = JPanel(BorderLayout())

            # Top toolbar panel with statistics and controls
            toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
            toolbar.setBackground(Color(240, 240, 240))
            
            # Statistics label
            self.stats_label = JLabel("Findings: 0")
            self.stats_label.setFont(Font("Dialog", Font.BOLD, 12))
            toolbar.add(self.stats_label)
            
            # Clear button
            clear_button = JButton("Clear Results")
            clear_button.addActionListener(ClearButtonListener(self))
            toolbar.add(clear_button)
            
            self.panel.add(toolbar, BorderLayout.NORTH)

            # Table UI
            panel_table = JPanel(BorderLayout())
            head = ['ID', 'Method', 'URL', 'Reflected Characters']
            self.tableModel = table.DefaultTableModel(self.data, head)
            
            self.myTable.setModel(self.tableModel) 
            self.myTable.setAutoCreateRowSorter(True)
            self.myTable.setRowHeight(25)
            self.myTable.setShowGrid(True)
            self.myTable.setGridColor(Color(220, 220, 220))
            
            # Adjust column widths
            self.myTable.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
            self.myTable.columnModel.getColumn(0).preferredWidth = 50
            self.myTable.columnModel.getColumn(0).setMaxWidth(80)
            self.myTable.columnModel.getColumn(1).preferredWidth = 80
            self.myTable.columnModel.getColumn(1).setMaxWidth(100)
            self.myTable.columnModel.getColumn(2).preferredWidth = 500
            self.myTable.columnModel.getColumn(3).preferredWidth = 150
            self.myTable.columnModel.getColumn(3).setMaxWidth(200)

            scrollPane = JScrollPane(self.myTable)
            panel_table.add(scrollPane, BorderLayout.CENTER)

            self.myTable.addMouseListener(MyMouseListener(self.myTable, self))
            self.myTable.addKeyListener(MyKeyListener(self.myTable, self))

            # Split pane for table and request/response viewers
            self.splitpane.setTopComponent(panel_table)
            self.splitpane.setBottomComponent(self.editor_panel)
            self.splitpane.setDividerLocation(300)
            self.splitpane.setResizeWeight(0.4)
            
            self.panel.add(self.splitpane, BorderLayout.CENTER)
        
        return self.panel
    
    def updateTable(self):
        self.tableModel.setDataVector(self.data, ['ID', 'Method', 'URL', 'Reflected Characters'])
        # Reapply column settings after data update
        self.myTable.columnModel.getColumn(0).preferredWidth = 50
        self.myTable.columnModel.getColumn(0).setMaxWidth(80)
        self.myTable.columnModel.getColumn(1).preferredWidth = 80
        self.myTable.columnModel.getColumn(1).setMaxWidth(100)
        self.myTable.columnModel.getColumn(2).preferredWidth = 500
        self.myTable.columnModel.getColumn(3).preferredWidth = 150
        self.myTable.columnModel.getColumn(3).setMaxWidth(200)
        # Update statistics
        if hasattr(self, 'stats_label'):
            self.stats_label.setText("Findings: " + str(len(self.data)))
    
    def clearResults(self):
        self.data = []
        self.data_requests = []
        self.data_responses = []
        self.tested_urls = set()
        self.id = 0
        self.updateTable()
        self._requestViewer.setMessage(None, True)
        self._responseViewer.setMessage(None, False)
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("isXSS")
        callbacks.addSuiteTab(self)
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        # Add Message Editors to UI in split pane for side-by-side view
        message_splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Request panel
        request_panel = JPanel(BorderLayout())
        request_label = JLabel("Request")
        request_label.setFont(Font("Dialog", Font.BOLD, 12))
        request_panel.add(request_label, BorderLayout.NORTH)
        request_panel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        
        # Response panel
        response_panel = JPanel(BorderLayout())
        response_label = JLabel("Response")
        response_label.setFont(Font("Dialog", Font.BOLD, 12))
        response_panel.add(response_label, BorderLayout.NORTH)
        response_panel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)
        
        message_splitpane.setLeftComponent(request_panel)
        message_splitpane.setRightComponent(response_panel)
        message_splitpane.setResizeWeight(0.5)
        
        self.editor_panel.add(message_splitpane, BorderLayout.CENTER)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if message received is a request or response
        if(messageIsRequest):
            try:
                request = messageInfo.getRequest()
                request_data = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
                headers = request_data.getHeaders()
                method = request_data.getMethod()
            
                # Get the parameters from the request
                parameters = request_data.getParameters()

                if(parameters == []):
                    return
                
                # Avoid testing duplicate URLs - create unique key from URL and method
                url = request_data.getUrl()
                url_key = str(url) + "|" + method
                if url_key in self.tested_urls:
                    return
                self.tested_urls.add(url_key)
                
                new_parameters = []
                
                # Loop over the parameters and modify as necessary
                for parameter in parameters:
                    if('ggg' in parameter.getValue()):
                        return
                    new_value = "ggg2\"ggg3>ggg4<"
                    new_parameter = self._helpers.buildParameter(parameter.getName(), new_value, parameter.getType())
                    new_parameters.append(new_parameter)

                modified_request = None
                
                # Handle GET requests
                if method == "GET":
                    # Create a new query string with the new parameters
                    new_query = '&'.join([p.getName() + '=' + p.getValue() for p in new_parameters])
                    # Replace the query string in the URL with the new query string
                    new_url = url.getProtocol() + "://" + url.getHost() + ":" + str(url.getPort()) + url.getPath() + "?" + new_query
                    if url.getRef():
                        new_url += "#" + url.getRef()
                    modified_request = self._helpers.buildHttpRequest(URL(new_url))
                
                # Handle POST requests
                elif method == "POST":
                    modified_request = request[:]
                    for param in new_parameters:
                        modified_request = self._helpers.updateParameter(modified_request, param)
                
                else:
                    # Unsupported method
                    return
                
                if modified_request:
                    new_request = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request)
                    new_request_data = self._helpers.analyzeRequest(new_request)
                        
                    url = new_request_data.getUrl()

                    # Get the response to the new request
                    response = new_request.getResponse()
                    if not response:
                        # Silent fail - no need to spam console for network issues
                        return
                        
                    response_data = self._helpers.analyzeResponse(response)

                    # Find response body and check if payload is reflected
                    response_body = response[response_data.getBodyOffset():]
                    if response_data.getBodyOffset() != -1:
                        reflected = []
                        response_body_str = self._helpers.bytesToString(response_body)
                        
                        if "ggg2\"" in response_body_str:
                            reflected.append("\"")
                        if "ggg3>" in response_body_str:
                            reflected.append(">")
                        if "ggg4<" in response_body_str:
                            reflected.append("<")
                        
                        # Check for DOM-based XSS sinks
                        import re
                        dom_sinks = []
                        
                        # 1. href attributes - only if ggg starts the value (not in parameters)
                        if re.search(r'href\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("href")
                        
                        # 2. Event handlers - payload must be at start of handler value
                        event_handlers = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 
                                        'onblur', 'onchange', 'onsubmit', 'onmouseout', 'onkeydown',
                                        'onkeyup', 'onkeypress', 'ondblclick', 'onmousedown', 'onmouseup']
                        for handler in event_handlers:
                            if re.search(handler + r'\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                                dom_sinks.append(handler)
                                break  # Just note that an event handler was found
                        
                        # 3. Dangerous src/data attributes - payload must be at start
                        if re.search(r'<script[^>]+src\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("script-src")
                        if re.search(r'<iframe[^>]+src\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("iframe-src")
                        if re.search(r'<embed[^>]+src\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("embed-src")
                        if re.search(r'<object[^>]+data\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("object-data")
                        
                        # 4. JavaScript execution contexts - directly in code
                        if re.search(r'<script[^>]*>[^<]*\bggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("script-context")
                        if re.search(r'\b(eval|setTimeout|setInterval)\s*\(\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("js-exec")
                        
                        # 5. DOM manipulation - directly assigned
                        if re.search(r'\b(innerHTML|outerHTML)\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("dom-write")
                        if re.search(r'document\.(write|writeln)\s*\(\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("dom-write")
                        
                        # 6. URL/Navigation - directly assigned
                        if re.search(r'\b(location|location\.href)\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("navigation")
                        if re.search(r'window\.open\s*\(\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("navigation")
                        
                        # 7. Form action - payload must be at start
                        if re.search(r'<form[^>]+action\s*=\s*["\']?\s*ggg', response_body_str, re.IGNORECASE):
                            dom_sinks.append("form-action")
                        
                        # Check response headers for reflections
                        response_headers = response_data.getHeaders()
                        header_reflection = False
                        for header in response_headers:
                            if "ggg" in header:
                                header_reflection = True
                                if "ggg2\"" in header and "\"" not in reflected:
                                    reflected.append("\"")
                                if "ggg3>" in header and ">" not in reflected:
                                    reflected.append(">")
                                if "ggg4<" in header and "<" not in reflected:
                                    reflected.append("<")
                                break
                        
                        if reflected or header_reflection or dom_sinks:
                            # Format the reflected characters nicely
                            reflected_parts = []
                            if reflected:
                                reflected_parts.append(", ".join(reflected))
                            if dom_sinks:
                                reflected_parts.append("[DOM:" + ",".join(dom_sinks) + "]")
                            if header_reflection and not reflected:
                                reflected_parts.append("(header only)")
                            
                            reflected_str = " ".join(reflected_parts) if reflected_parts else "(detected)"
                            self.data.append([self.id, new_request_data.getMethod(), str(new_request_data.getUrl()), reflected_str]) 
                            self.id = self.id + 1 
                            self.data_requests.append(modified_request) 
                            self.data_responses.append(response) 

                            # Update the JTable after updating the data
                            self.updateTable()
                        
            except Exception as e:
                # Log error quietly without stack trace for common issues
                error_msg = str(e)
                if "java.net" in error_msg or "connection" in error_msg.lower():
                    # Network errors are common, don't spam console
                    pass
                else:
                    # For unexpected errors, provide helpful message
                    print("[isXSS] Unexpected error - " + error_msg)
