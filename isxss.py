from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IHttpRequestResponse, IHttpService, IParameter
from javax.swing import JFrame, JPanel, JTable, JScrollPane, JTextArea, table, BoxLayout, JTabbedPane, JSplitPane
from java.awt import BorderLayout, Color, Dimension
from java.awt.event import MouseAdapter, KeyEvent, KeyAdapter
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
        row = self.table.getSelectedRow()
        if row != -1 and e.getKeyCode() == KeyEvent.VK_UP or e.getKeyCode() == KeyEvent.VK_DOWN:
            self.extender._requestViewer.setMessage(self.extender.data_requests[row], True)
            self.extender._responseViewer.setMessage(self.extender.data_responses[row], False)

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
        self.splitpane.setPreferredSize(Dimension(800,450))
        self.myTable = JTable()
        self._requestViewer = any
        self._responseViewer = any
        self.editor_panel = JPanel(BorderLayout())

    def getTabCaption(self):
        return "isXSS"

    def getUiComponent(self):
        if not self.panel:  # Only create panel once
            panel = JPanel(BorderLayout())

            # Tabel UI
            panel_table = JPanel()
            panel_table.setLayout(BoxLayout(panel_table, BoxLayout.Y_AXIS))
            head = ['ID', 'Method', 'URL', 'XSS']
            self.tableModel = table.DefaultTableModel(self.data, head)
            
            self.myTable.setModel(self.tableModel) 
            self.myTable.setAutoCreateRowSorter(True)
            panel_table.add(self.myTable.getTableHeader())
            panel_table.add(JScrollPane(self.myTable))
            self.myTable.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
            self.myTable.columnModel.getColumn(0).preferredWidth = 10
            self.myTable.columnModel.getColumn(1).preferredWidth = 10
            self.myTable.columnModel.getColumn(2).preferredWidth = 550
            self.myTable.columnModel.getColumn(3).preferredWidth = 50

            self.myTable.addMouseListener(MyMouseListener(self.myTable, self))
            self.myTable.addKeyListener(MyKeyListener(self.myTable, self))

            # Add UI to Panel
            panel.add(panel_table)
            panel.add(self.splitpane, BorderLayout.SOUTH)
        return panel
    
    def updateTable(self):
        self.tableModel.setDataVector(self.data, ['ID', 'Method', 'URL' ,'XSS'])
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("isXSS")
        callbacks.addSuiteTab(self)
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        # Add Message Editor to UI
        tabs = JTabbedPane()
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self.editor_panel.add(tabs)
        self.splitpane.setLeftComponent(self.editor_panel)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if message received is a request or response
        if(messageIsRequest):
            request = messageInfo.getRequest()
            request_data = self._helpers.analyzeRequest(messageInfo.getHttpService(), request)
            headers = request_data.getHeaders()
            method = request_data.getMethod()
        
            # Get the parameters from the request
            parameters = request_data.getParameters()

            if(parameters == []):
                return
            
            new_parameters = []
            
            # Loop over the parameters and modify as necessary
            for parameter in parameters:
                if('xxxx' in parameter.getValue()):
                    return
                new_value = "xxxx1'xxxx2\"xxxx3>xxxx4<"
                new_parameter = self._helpers.buildParameter(parameter.getName(), new_value, parameter.getType())
                new_parameters.append(new_parameter)

            url = request_data.getUrl()

            # Create a new query string with the new parameters
            new_query = '&'.join([p.getName() + '=' + p.getValue() for p in new_parameters])

            # Replace the query string in the URL with the new query string
            new_url = url.getProtocol() + "://" + url.getHost() + ":" + str(url.getPort()) + url.getPath() + "?" + new_query
            if url.getRef():
                new_url += "#" + url.getRef()

            try:
                if method == "GET":
                    # Use the new URL with modified parameters
                    modified_request = self._helpers.buildHttpRequest(URL(new_url))
                    new_request = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request)
                    new_request_data = self._helpers.analyzeRequest(new_request)
                        
                    url = new_request_data.getUrl()

                    # Check if the URL is within the current scope
                    if not self._callbacks.isInScope(url):
                        return

                    # Get the response to the new request
                    response = new_request.getResponse()
                    response_data = self._helpers.analyzeResponse(response)

                    # Find response body and check if "XSS" is reflected
                    response_body = response[response_data.getBodyOffset():]
                    if response_data.getBodyOffset() != -1:
                        reflected = []
                        if "xxxx1'" in self._helpers.bytesToString(response_body):
                            reflected.append("'")
                        if "xxxx2\"" in self._helpers.bytesToString(response_body):
                            reflected.append("\"")
                        if "xxxx3>" in self._helpers.bytesToString(response_body):
                            reflected.append(">")
                        if "xxxx4<" in self._helpers.bytesToString(response_body):
                            reflected.append("<")
                        
                        # self.data.append([self.id, new_request_data.getMethod(), new_request_data.getUrl(), reflected]) # DEBUG
                        # self.id = self.id + 1 # DEBUG
                        # self.data_requests.append(modified_request) # DEBUG
                        # self.data_responses.append(response) # DEBUG
                        # print(self.data)
                        if(reflected):
                            self.data.append([self.id, new_request_data.getMethod(), new_request_data.getUrl(), reflected]) 
                            self.id = self.id + 1 
                            self.data_requests.append(modified_request) 
                            self.data_responses.append(response) 

                            # Update the JTable after updating the data
                            self.updateTable()
                        
                    else:
                        print("No response body")
            except Exception as e:
                print(e)
